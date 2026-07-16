package in.blazenxt.vault100;

import android.app.Activity;
import android.content.ClipData;
import android.content.Intent;
import android.net.Uri;
import android.os.Bundle;
import android.util.Base64;
import android.webkit.JavascriptInterface;
import android.webkit.ValueCallback;
import android.webkit.WebChromeClient;
import android.webkit.WebResourceRequest;
import android.webkit.WebResourceResponse;
import android.webkit.WebSettings;
import android.webkit.WebView;
import android.webkit.WebViewClient;
import android.widget.Toast;

import java.io.ByteArrayInputStream;
import java.io.File;
import java.io.FileOutputStream;
import java.io.InputStream;
import java.io.OutputStream;
import java.util.ArrayDeque;
import java.util.HashMap;
import java.util.Map;

/**
 * Vault100 Pocket Annex — the entire seal bureau folded into a handset.
 *
 * Every page, script and primitive ships inside the APK under assets/webroot
 * and is served to the WebView from a private https origin
 * (https://appassets.androidplatform.net/). The app requests ZERO Android
 * permissions — not even INTERNET — so the vault is offline by physics, not
 * by policy. Encryption/decryption still happens in the page's web worker
 * (Argon2id + XChaCha20-Poly1305); this shell only:
 *   1. delivers static filings to the window,
 *   2. opens the system tray when a page needs a file (onShowFileChooser),
 *   3. relays finished filings (VB.download) into the system save dialog,
 *      ticketed so several filings can queue without tripping each other.
 */
public class MainActivity extends Activity {
    private static final String ORIGIN = "appassets.androidplatform.net";
    private static final int REQ_PICK = 7001;
    private static final int REQ_SAVE = 7002;

    private WebView web;
    private ValueCallback<Uri[]> fileCallback;

    // ---- the save relay: spooled filings awaiting the system save tray ----
    private final Map<Integer, Spool> spools = new HashMap<Integer, Spool>();
    private final ArrayDeque<Integer> safQueue = new ArrayDeque<Integer>();
    private int nextTicket = 1;
    private int currentSafTicket = -1;

    private static class Spool { File file; FileOutputStream out; String name; }

    @Override
    public void onCreate(Bundle state) {
        super.onCreate(state);
        getWindow().setStatusBarColor(0xFF121317);
        getWindow().setNavigationBarColor(0xFF121317);
        web = new WebView(this);
        web.setBackgroundColor(0xFF121317);
        setContentView(web);

        WebSettings s = web.getSettings();
        s.setJavaScriptEnabled(true);
        s.setDomStorageEnabled(true);
        s.setAllowFileAccess(false);
        s.setAllowContentAccess(false);

        web.addJavascriptInterface(new VaultBridge(), "AndroidVault");
        web.setWebViewClient(new BureauClient());
        web.setWebChromeClient(new BureauChrome());
        web.loadUrl("https://" + ORIGIN + "/");
    }

    @Override
    public void onDestroy() {
        if (web != null) web.destroy();
        super.onDestroy();
    }

    @Override
    public void onBackPressed() {
        if (web != null && web.canGoBack()) web.goBack();
        else super.onBackPressed();
    }

    // ---------------- the window: serve bundled filings, nothing else --------
    private class BureauClient extends WebViewClient {
        @Override
        public WebResourceResponse shouldInterceptRequest(WebView v, WebResourceRequest r) {
            Uri u = r.getUrl();
            if (!ORIGIN.equals(u.getHost())) return refuse(403, "no outside calls at this window");
            String path = u.getPath();
            if (path == null || path.equals("") || path.equals("/")) path = "/index.html";
            if (path.contains("..")) return refuse(403, "no such form");
            try {
                InputStream in = getAssets().open("webroot" + path);
                return new WebResourceResponse(mimeOf(path), charsetOf(path), in);
            } catch (Exception e) {
                return refuse(404, "the annex holds no such form");
            }
        }

        @Override
        public boolean shouldOverrideUrlLoading(WebView v, WebResourceRequest r) {
            String u = r.getUrl().toString();
            if (u.startsWith("https://" + ORIGIN + "/")) return false;
            // foreign post (GitHub, email…) is handed to the real browser
            try { startActivity(new Intent(Intent.ACTION_VIEW, Uri.parse(u))); } catch (Exception ignored) {}
            return true;
        }
    }

    private WebResourceResponse refuse(int code, String why) {
        WebResourceResponse rr = new WebResourceResponse(
                "text/plain", "UTF-8", new ByteArrayInputStream(new byte[0]));
        rr.setStatusCodeAndReasonPhrase(code, why);
        return rr;
    }

    private static String mimeOf(String p) {
        if (p.endsWith(".html")) return "text/html";
        if (p.endsWith(".js"))   return "text/javascript";
        if (p.endsWith(".css"))  return "text/css";
        if (p.endsWith(".json")) return "application/json";
        if (p.endsWith(".wasm")) return "application/wasm";
        if (p.endsWith(".svg"))  return "image/svg+xml";
        if (p.endsWith(".png"))  return "image/png";
        if (p.endsWith(".jpg") || p.endsWith(".jpeg")) return "image/jpeg";
        if (p.endsWith(".ico"))  return "image/x-icon";
        if (p.endsWith(".xml"))  return "application/xml";
        if (p.endsWith(".txt") || p.endsWith(".asc") || p.endsWith(".v100asc")) return "text/plain";
        return "application/octet-stream";
    }

    private static String charsetOf(String p) {
        String m = mimeOf(p);
        return (m.startsWith("text/") || p.endsWith(".json") || p.endsWith(".xml") || p.endsWith(".svg"))
                ? "UTF-8" : null;
    }

    // ---------------- intake: the system tray for choosing papers ------------
    private class BureauChrome extends WebChromeClient {
        @Override
        public boolean onShowFileChooser(WebView v, ValueCallback<Uri[]> cb,
                                         FileChooserParams params) {
            if (fileCallback != null) { fileCallback.onReceiveValue(null); fileCallback = null; }
            fileCallback = cb;
            Intent i;
            try { i = params.createIntent(); }
            catch (Exception e) {
                i = new Intent(Intent.ACTION_GET_CONTENT);
                i.setType("*/*");
            }
            i.addCategory(Intent.CATEGORY_OPENABLE);
            try { startActivityForResult(i, REQ_PICK); }
            catch (Exception e) { fileCallback = null; return false; }
            return true;
        }
    }

    @Override
    protected void onActivityResult(int req, int res, Intent data) {
        if (req == REQ_PICK) {
            Uri[] out = null;
            if (res == RESULT_OK && data != null) {
                ClipData cd = data.getClipData();
                if (cd != null) {
                    out = new Uri[cd.getItemCount()];
                    for (int i = 0; i < cd.getItemCount(); i++) out[i] = cd.getItemAt(i).getUri();
                } else if (data.getData() != null) {
                    out = new Uri[]{ data.getData() };
                }
            }
            if (fileCallback != null) { fileCallback.onReceiveValue(out); fileCallback = null; }
            return;
        }
        if (req == REQ_SAVE) {
            int t = currentSafTicket;
            currentSafTicket = -1;
            if (t != -1) {
                if (res == RESULT_OK && data != null && data.getData() != null) {
                    deliverSpool(t, data.getData());
                } else {
                    discardSpool(t);
                    toast("save annulled — the filing stays on the counter.");
                }
                ackJs(t);
            }
            pumpSafQueue();
            return;
        }
        super.onActivityResult(req, res, data);
    }

    // ---------------- the relay bridge: VB.download → system save tray -------
    private class VaultBridge {
        @JavascriptInterface
        public synchronized int begin(String name, long size) {
            int t = nextTicket++;
            try {
                Spool sp = new Spool();
                sp.name = sanitize(name);
                sp.file = new File(getCacheDir(), "vault100-spool-" + t + ".bin");
                sp.out = new FileOutputStream(sp.file);
                spools.put(t, sp);
            } catch (Exception e) {
                toast("the annex could not open a spool.");
            }
            return t;
        }

        @JavascriptInterface
        public synchronized void append(int t, String b64) {
            Spool sp = spools.get(t);
            if (sp == null || sp.out == null) return;
            try { sp.out.write(Base64.decode(b64, Base64.DEFAULT)); }
            catch (Exception e) { toast("the relay tore mid-filing."); }
        }

        @JavascriptInterface
        public synchronized void finish(int t) {
            Spool sp = spools.get(t);
            if (sp == null) { ackJs(t); return; }
            try { if (sp.out != null) { sp.out.flush(); sp.out.close(); } } catch (Exception ignored) {}
            sp.out = null;
            final int ticket = t;
            runOnUiThread(new Runnable() {
                public void run() {
                    if (currentSafTicket != -1) { safQueue.add(ticket); return; }
                    launchSaf(ticket);
                }
            });
        }
    }

    private synchronized void launchSaf(int t) {
        Spool sp = spools.get(t);
        if (sp == null) { ackJs(t); pumpSafQueue(); return; }
        currentSafTicket = t;
        Intent i = new Intent(Intent.ACTION_CREATE_DOCUMENT);
        i.addCategory(Intent.CATEGORY_OPENABLE);
        i.setType("*/*");
        i.putExtra(Intent.EXTRA_TITLE, sp.name);
        try { startActivityForResult(i, REQ_SAVE); }
        catch (Exception e) {
            toast("no clerk here to receive the filing.");
            discardSpool(t);
            ackJs(t);
            currentSafTicket = -1;
            pumpSafQueue();
        }
    }

    private synchronized void pumpSafQueue() {
        if (currentSafTicket != -1) return;
        Integer nxt = safQueue.poll();
        if (nxt != null) launchSaf(nxt);
    }

    private void deliverSpool(int t, Uri uri) {
        Spool sp;
        synchronized (this) { sp = spools.get(t); }
        if (sp == null) return;
        long total = sp.file.length();
        boolean ok = false;
        try (InputStream in = new java.io.FileInputStream(sp.file);
             OutputStream outf = getContentResolver().openOutputStream(uri)) {
            byte[] buf = new byte[65536];
            int n;
            while ((n = in.read(buf)) != -1) outf.write(buf, 0, n);
            outf.flush();
            ok = true;
        } catch (Exception e) { ok = false; }
        discardSpool(t);
        toast(ok ? "filing delivered — " + total + " B sealed where you chose."
                 : "the filing could not be delivered.");
    }

    private synchronized void discardSpool(int t) {
        Spool sp = spools.remove(t);
        if (sp == null) return;
        try { if (sp.out != null) sp.out.close(); } catch (Exception ignored) {}
        if (sp.file != null && sp.file.exists()) sp.file.delete();
    }

    private void ackJs(final int t) {
        runOnUiThread(new Runnable() {
            public void run() {
                if (web != null)
                    web.evaluateJavascript("window.__v100ack&&window.__v100ack(" + t + ");", null);
            }
        });
    }

    private static String sanitize(String n) {
        String s = n == null ? "" : n.replaceAll("[^A-Za-z0-9._()\\- ]", "_");
        if (s.length() > 96) s = s.substring(s.length() - 96);
        if (s.trim().isEmpty()) s = "vault100.bin";
        return s;
    }

    private void toast(final String msg) {
        runOnUiThread(new Runnable() {
            public void run() { Toast.makeText(MainActivity.this, msg, Toast.LENGTH_LONG).show(); }
        });
    }
}
