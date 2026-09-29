package ru.moon.checker.net;

import ru.moon.checker.core.Log;

import javax.net.ssl.SSLContext;
import javax.net.ssl.TrustManager;
import javax.net.ssl.TrustManagerFactory;
import javax.net.ssl.X509TrustManager;
import java.net.http.HttpClient;
import java.security.KeyStore;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.time.Duration;
import java.util.ArrayList;
import java.util.List;

/**
 * Network defaults for players' PCs.
 *
 * <ul>
 *   <li><b>System proxy:</b> {@code java.net.useSystemProxies} is switched on before
 *       any connection, so the Windows proxy settings apply (office and dormitory
 *       networks, some VPN clients).</li>
 *   <li><b>Trust:</b> the JDK's own CA list (which includes Let's Encrypt's ISRG
 *       roots) <em>or</em> the Windows root store. Antivirus HTTPS scanning — on by
 *       default in popular suites in Russia — re-signs TLS with its own root, which it
 *       adds to Windows but not to Java, and every connection then failed with
 *       "PKIX path building failed". Accepting the Windows store matches what the
 *       browser on the same PC accepts; report integrity does not rely on TLS alone
 *       (the panel verifies the bundle's hash and code).</li>
 * </ul>
 */
public final class NetSetup {

    private static volatile SSLContext context;

    private NetSetup() {
    }

    /** Call first thing in main(), before anything opens a connection. */
    public static void init() {
        if (System.getProperty("java.net.useSystemProxies") == null) {
            System.setProperty("java.net.useSystemProxies", "true");
        }
    }

    /** An HttpClient builder with the defaults above. */
    public static HttpClient.Builder client(Duration connectTimeout) {
        HttpClient.Builder b = HttpClient.newBuilder().connectTimeout(connectTimeout);
        SSLContext ctx = sslContext();
        if (ctx != null) {
            b.sslContext(ctx);
        }
        return b;
    }

    /** JDK CAs plus, on Windows, the Windows root store; null to use the JDK default. */
    static SSLContext sslContext() {
        SSLContext c = context;
        if (c == null) {
            synchronized (NetSetup.class) {
                c = context;
                if (c == null) {
                    c = build();
                    context = c;
                }
            }
        }
        return c;
    }

    private static SSLContext build() {
        try {
            List<X509TrustManager> managers = new ArrayList<>();
            X509TrustManager jdk = trustManager(null);
            if (jdk != null) {
                managers.add(jdk);
            }
            try {
                KeyStore windows = KeyStore.getInstance("Windows-ROOT");
                windows.load(null, null);
                X509TrustManager win = trustManager(windows);
                if (win != null) {
                    managers.add(win);
                }
            } catch (Exception e) {
                // not Windows, or the provider is missing: the JDK list alone
            }
            SSLContext ctx = SSLContext.getInstance("TLS");
            ctx.init(null, new TrustManager[]{new AnyOf(managers)}, null);
            return ctx;
        } catch (Exception e) {
            Log.warn("TLS trust setup failed; using the JDK default", e);
            return null;
        }
    }

    private static X509TrustManager trustManager(KeyStore ks) throws Exception {
        TrustManagerFactory tmf = TrustManagerFactory.getInstance(TrustManagerFactory.getDefaultAlgorithm());
        tmf.init(ks);
        for (TrustManager tm : tmf.getTrustManagers()) {
            if (tm instanceof X509TrustManager x) {
                return x;
            }
        }
        return null;
    }

    /** Trusts a chain when any of its delegates does; reports the first delegate's error otherwise. */
    static final class AnyOf implements X509TrustManager {
        private final List<X509TrustManager> delegates;

        AnyOf(List<X509TrustManager> delegates) {
            this.delegates = List.copyOf(delegates);
        }

        @Override
        public void checkClientTrusted(X509Certificate[] chain, String authType) throws CertificateException {
            check(chain, authType, true);
        }

        @Override
        public void checkServerTrusted(X509Certificate[] chain, String authType) throws CertificateException {
            check(chain, authType, false);
        }

        private void check(X509Certificate[] chain, String authType, boolean client) throws CertificateException {
            CertificateException first = null;
            for (X509TrustManager tm : delegates) {
                try {
                    if (client) {
                        tm.checkClientTrusted(chain, authType);
                    } else {
                        tm.checkServerTrusted(chain, authType);
                    }
                    return;
                } catch (CertificateException e) {
                    if (first == null) {
                        first = e;
                    }
                }
            }
            throw first != null ? first : new CertificateException("no trust managers");
        }

        @Override
        public X509Certificate[] getAcceptedIssuers() {
            List<X509Certificate> all = new ArrayList<>();
            for (X509TrustManager tm : delegates) {
                all.addAll(List.of(tm.getAcceptedIssuers()));
            }
            return all.toArray(new X509Certificate[0]);
        }
    }
}
