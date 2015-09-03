using System;
using System.Threading;
using System.Threading.Tasks;
using System.Collections.Generic;
using System.Linq;
using System.Net;
using System.Net.Http;
using OkHttp;
using Javax.Net.Ssl;
using System.Text.RegularExpressions;
using Java.IO;
using System.Security.Cryptography.X509Certificates;
using System.Globalization;
using Android.OS;

namespace ModernHttpClient
{
    public class OkHttpNetworkHandler : HttpClientHandler
    {
        public readonly OkHttpClient client = new OkHttpClient();
        readonly bool throwOnCaptiveNetwork;

        readonly Dictionary<HttpRequestMessage, WeakReference> registeredProgressCallbacks =
            new Dictionary<HttpRequestMessage, WeakReference>();

        public void CloseConnections() {
            ConnectionPool.Default.EvictAll();
        }

        private void JavaExceptionMapper(Exception e)
        {
            if (e is Java.Net.UnknownHostException)
                throw new WebException("Name resolution failure", e, WebExceptionStatus.NameResolutionFailure, null);
            if (e is Java.IO.IOException) {
                var msg = e.ToString();
                if(msg.Contains("Hostname") && msg.Contains("was not verified"))
                    CloseConnections();
                throw new WebException("IO Exception", e, WebExceptionStatus.ConnectFailure, null);
            }
        }


        public OkHttpNetworkHandler() : this(false, false) {}

        public OkHttpNetworkHandler(bool throwOnCaptiveNetwork, bool customSSLVerification)
        {
            this.throwOnCaptiveNetwork = throwOnCaptiveNetwork;

            if (customSSLVerification) client.SetHostnameVerifier(new HostnameVerifier());
        }

        public void RegisterForProgress(HttpRequestMessage request, ProgressDelegate callback)
        {
            if (callback == null && registeredProgressCallbacks.ContainsKey(request)) {
                registeredProgressCallbacks.Remove(request);
                return;
            }

            registeredProgressCallbacks[request] = new WeakReference(callback);
        }

        ProgressDelegate getAndRemoveCallbackFromRegister(HttpRequestMessage request)
        {
            ProgressDelegate emptyDelegate = delegate { };

            lock (registeredProgressCallbacks) {
                if (!registeredProgressCallbacks.ContainsKey(request)) return emptyDelegate;

                var weakRef = registeredProgressCallbacks[request];
                if (weakRef == null) return emptyDelegate;

                var callback = weakRef.Target as ProgressDelegate;
                if (callback == null) return emptyDelegate;

                registeredProgressCallbacks.Remove(request);
                return callback;
            }
        }
        protected override async Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken cancellationToken)
        {
            try {
                return await InternalSendAsync(request, cancellationToken);
            } catch(Exception e) {
                JavaExceptionMapper(e);
                throw e;
            }
        }
        protected async Task<HttpResponseMessage> InternalSendAsync(HttpRequestMessage request, CancellationToken cancellationToken)
        {
            var java_uri = request.RequestUri.GetComponents(UriComponents.AbsoluteUri, UriFormat.UriEscaped);
            var url = new Java.Net.URL(java_uri);

            var body = default(RequestBody);
            if (request.Content != null) {
                var bytes = await request.Content.ReadAsByteArrayAsync().ConfigureAwait(false);

                var contentType = String.Join (" ", request.Content.Headers.GetValues ("Content-Type"));
                body = RequestBody.Create(MediaType.Parse(contentType), bytes);
            }

            var builder = new Request.Builder()
                .Method(request.Method.Method.ToUpperInvariant(), body)
                .Url(url);

            var keyValuePairs = request.Headers
                .Union(request.Content != null ?
                    (IEnumerable<KeyValuePair<string, IEnumerable<string>>>)request.Content.Headers :
                    Enumerable.Empty<KeyValuePair<string, IEnumerable<string>>>());

            foreach (var kvp in keyValuePairs) builder.AddHeader(kvp.Key, String.Join(",", kvp.Value));

            cancellationToken.ThrowIfCancellationRequested();

            var rq = builder.Build();
            var call = client.NewCall(rq);

            // NB: Even closing a socket must be done off the UI thread. Cray!
            cancellationToken.Register(() => Task.Run(() => call.Cancel()));

            var resp = default(Response);
            try {
                resp = await Task.Run(() => call.Execute());
                var newReq = resp.Request();
                var newUri = newReq == null ? null : newReq.Uri();
                if (throwOnCaptiveNetwork && newUri != null) {
                    if (url.Host != newUri.Host) {
                        throw new CaptiveNetworkException(new Uri(java_uri), new Uri(newUri.ToString()));
                    }
                }
            } catch (IOException ex) {
                if (ex.Message.ToLowerInvariant().Contains("canceled")) {
                    throw new OperationCanceledException();
                }

                throw;
            }

            var respBody = resp.Body();

            cancellationToken.ThrowIfCancellationRequested();

            var ret = new HttpResponseMessage((HttpStatusCode)resp.Code());
            ret.RequestMessage = request;
            ret.ReasonPhrase = resp.Message();
            if (respBody != null) {
                var content = new ProgressStreamContent(respBody.ByteStream(), CancellationToken.None, JavaExceptionMapper);
                content.Progress = getAndRemoveCallbackFromRegister(request);
                ret.Content = content;
            } else {
                ret.Content = new ByteArrayContent(new byte[0]);
            }

            var respHeaders = resp.Headers();
            foreach (var k in respHeaders.Names()) {
                ret.Headers.TryAddWithoutValidation(k, respHeaders.Get(k));
                ret.Content.Headers.TryAddWithoutValidation(k, respHeaders.Get(k));
            }

            return ret;
        }
    }

    class HostnameVerifier : Java.Lang.Object, IHostnameVerifier
    {
        static readonly Regex cnRegex = new Regex(@"CN\s*=\s*([^,]*)", RegexOptions.Compiled | RegexOptions.CultureInvariant | RegexOptions.Singleline);

        public bool Verify(string hostname, ISSLSession session)
        {
            return verifyServerCertificate(hostname, session) & verifyClientCiphers(hostname, session);
        }

        /// <summary>
        /// Verifies the server certificate by calling into ServicePointManager.ServerCertificateValidationCallback or,
        /// if the is no delegate attached to it by using the default hostname verifier.
        /// </summary>
        /// <returns><c>true</c>, if server certificate was verifyed, <c>false</c> otherwise.</returns>
        /// <param name="hostname"></param>
        /// <param name="session"></param>
        bool verifyServerCertificate(string hostname, ISSLSession session)
        {
            var defaultVerifier = HttpsURLConnection.DefaultHostnameVerifier;

            if (ServicePointManager.ServerCertificateValidationCallback == null) return defaultVerifier.Verify(hostname, session);

            // Convert java certificates to .NET certificates and build cert chain from root certificate
            var certificates = session.GetPeerCertificateChain();
            var chain = new System.Security.Cryptography.X509Certificates.X509Chain();
            System.Security.Cryptography.X509Certificates.X509Certificate2 root = null;
            var errors = System.Net.Security.SslPolicyErrors.None;

            // Build certificate chain and check for errors
            if (certificates == null || certificates.Length == 0) {//no cert at all
                errors = System.Net.Security.SslPolicyErrors.RemoteCertificateNotAvailable;
                goto bail;
            } 

            if (certificates.Length == 1) {//no root?
                errors = System.Net.Security.SslPolicyErrors.RemoteCertificateChainErrors;
                goto bail;
            } 

            var netCerts = certificates.Select(x => new System.Security.Cryptography.X509Certificates.X509Certificate2(x.GetEncoded())).ToArray();

            for (int i = 1; i < netCerts.Length; i++) {
                chain.ChainPolicy.ExtraStore.Add(netCerts[i]);
            }

            root = netCerts[0];

            chain.ChainPolicy.RevocationFlag = System.Security.Cryptography.X509Certificates.X509RevocationFlag.EntireChain;
            chain.ChainPolicy.RevocationMode = System.Security.Cryptography.X509Certificates.X509RevocationMode.NoCheck;
            chain.ChainPolicy.UrlRetrievalTimeout = new TimeSpan(0, 1, 0);
            chain.ChainPolicy.VerificationFlags = 
                    System.Security.Cryptography.X509Certificates.X509VerificationFlags.AllowUnknownCertificateAuthority;

            if (!chain.Build(root)) {
                errors = System.Net.Security.SslPolicyErrors.RemoteCertificateChainErrors;
                goto bail;
            }

            var subject = root.Subject;
            var subjectCn = cnRegex.Match(subject).Groups[1].Value;

            if (String.IsNullOrWhiteSpace(subjectCn) || !Utility.MatchHostnameToPattern(hostname, subjectCn)) {
                errors = System.Net.Security.SslPolicyErrors.RemoteCertificateNameMismatch;
                goto bail;
            }

        bail:
            // Call the delegate to validate
            return ServicePointManager.ServerCertificateValidationCallback(this, root, chain, errors);
        }

        /// <summary>
        /// Verifies client ciphers and is only available in Mono and Xamarin products.
        /// </summary>
        /// <returns><c>true</c>, if client ciphers was verifyed, <c>false</c> otherwise.</returns>
        /// <param name="hostname"></param>
        /// <param name="session"></param>
        bool verifyClientCiphers(string hostname, ISSLSession session)
        {
            var callback = ServicePointManager.ClientCipherSuitesCallback;
            if (callback == null) return true;

            var protocol = session.Protocol.StartsWith("SSL", StringComparison.InvariantCulture) ? SecurityProtocolType.Ssl3 : SecurityProtocolType.Tls;
            var acceptedCiphers = callback(protocol, new[] { session.CipherSuite });

            return acceptedCiphers.Contains(session.CipherSuite);
        }
    }
}
