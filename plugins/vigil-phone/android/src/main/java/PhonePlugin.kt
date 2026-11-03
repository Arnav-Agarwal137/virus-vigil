package com.arnav.vigilphone

import android.accessibilityservice.AccessibilityServiceInfo
import android.app.Activity
import android.app.AppOpsManager
import android.app.KeyguardManager
import android.app.admin.DevicePolicyManager
import android.content.ActivityNotFoundException
import android.content.Context
import android.content.Intent
import android.content.pm.ApplicationInfo
import android.content.pm.PackageInfo
import android.content.pm.PackageManager
import android.net.ConnectivityManager
import android.net.NetworkCapabilities
import android.net.Uri
import android.net.wifi.WifiInfo
import android.os.Build
import android.os.Environment
import android.os.storage.StorageManager
import android.provider.OpenableColumns
import android.provider.Settings
import android.content.ComponentName
import android.provider.Telephony
import android.view.accessibility.AccessibilityManager
import android.webkit.WebView
import app.tauri.annotation.Command
import app.tauri.annotation.InvokeArg
import app.tauri.annotation.TauriPlugin
import app.tauri.plugin.Invoke
import app.tauri.plugin.JSArray
import app.tauri.plugin.JSObject
import app.tauri.plugin.Plugin
import org.json.JSONObject
import java.io.File
import java.net.HttpURLConnection
import java.net.URL

@InvokeArg
class SettingsArgs {
  lateinit var page: String
  var pkg: String? = null
}

@InvokeArg
class UriArgs {
  lateinit var uri: String
}

@InvokeArg
class PrefixArgs {
  lateinit var prefix: String
}

@InvokeArg
class HashesArgs {
  lateinit var hashes: Array<String>
}

@InvokeArg
class DownloadArgs {
  lateinit var dest: String
  /** Which phishing list: "pdb" = Phishing.Database (the default, as before), "certpl" = CERT Polska. */
  var source: String = "pdb"
}

@InvokeArg
class HashListArgs {
  lateinit var dest: String
  var full: Boolean = false
  /** abuse.ch Auth-Key (checked by Rust); empty = the old keyless address, which now says 410. */
  var key: String = ""
}

@InvokeArg
class OnlineArgs {
  lateinit var body: String
  lateinit var key: String
}

/**
 * Everything Virus Vigil reads on a phone. Read-only: nothing here changes a setting; the
 * only "action" is opening one of Android's own Settings pages for the person to act on.
 * Heavy or network work runs on its own thread; every command answers exactly once.
 */
@TauriPlugin
class PhonePlugin(private val activity: Activity) : Plugin(activity) {
  private val ctx: Context get() = activity.applicationContext

  // What another app shared into Vigil ("Share" -> Virus Vigil), waiting for the page.
  @Volatile private var sharedText: String? = null
  @Volatile private var sharedFile: String? = null

  override fun load(webView: WebView) {
    super.load(webView)
    readShare(activity.intent)
  }

  override fun onNewIntent(intent: Intent) {
    readShare(intent)
  }

  private fun readShare(intent: Intent?) {
    if (intent == null || intent.action != Intent.ACTION_SEND) return
    val text = listOfNotNull(
      intent.getStringExtra(Intent.EXTRA_SUBJECT),
      intent.getStringExtra(Intent.EXTRA_TEXT)
    ).joinToString("\n").trim()
    if (text.isNotEmpty()) sharedText = text.take(5000)
    @Suppress("DEPRECATION")
    val stream = intent.getParcelableExtra<Uri>(Intent.EXTRA_STREAM)
    if (stream != null) sharedFile = stream.toString()
    // Consume it, so a screen rotation does not deliver the same share twice.
    intent.action = Intent.ACTION_MAIN
  }

  private fun background(invoke: Invoke, work: () -> JSObject) {
    Thread {
      try {
        invoke.resolve(work())
      } catch (e: Throwable) {
        invoke.reject(e.message ?: e.javaClass.simpleName)
      }
    }.start()
  }

  // ---------------------------------------------------------------- the checkup

  @Command
  fun scan(invoke: Invoke) = background(invoke) {
    val out = JSObject()
    out.put("android", JSObject().apply {
      put("sdk", Build.VERSION.SDK_INT)
      put("release", Build.VERSION.RELEASE)
      put("patch", if (Build.VERSION.SDK_INT >= 23) Build.VERSION.SECURITY_PATCH else null)
      put("maker", Build.MANUFACTURER)
      put("model", Build.MODEL)
    })
    out.put("lock", guard { (ctx.getSystemService(Context.KEYGUARD_SERVICE) as KeyguardManager).isDeviceSecure })
    val dpm = ctx.getSystemService(Context.DEVICE_POLICY_SERVICE) as DevicePolicyManager
    out.put("encryption", guard { dpm.storageEncryptionStatus })
    out.put("accessibility", guard {
      val am = ctx.getSystemService(Context.ACCESSIBILITY_SERVICE) as AccessibilityManager
      val arr = JSArray()
      am.getEnabledAccessibilityServiceList(AccessibilityServiceInfo.FEEDBACK_ALL_MASK)
        .map { it.resolveInfo.serviceInfo.packageName }.distinct()
        .forEach { arr.put(appRef(it)) }
      arr
    })
    // Apps allowed to read every notification (OTP codes, bank alerts, chats) - the other power
    // banking Trojans and spy apps ask for. Same setting NotificationManagerCompat reads.
    out.put("notifReaders", guard {
      val arr = JSArray()
      (Settings.Secure.getString(ctx.contentResolver, "enabled_notification_listeners") ?: "")
        .split(":").mapNotNull { ComponentName.unflattenFromString(it)?.packageName }.distinct()
        .forEach { arr.put(appRef(it)) }
      arr
    })
    out.put("admins", guard {
      val arr = JSArray()
      (dpm.activeAdmins ?: emptyList()).map { it.packageName }.distinct().forEach { arr.put(appRef(it)) }
      arr
    })
    out.put("sms", guard { Telephony.Sms.getDefaultSmsPackage(ctx)?.let { appRef(it) } })
    out.put("wifi", guard { wifi() })
    out.put("apps", guard { apps() })
    out.put("systemApps", guard { systemApps() })
    out
  }

  /** The apps the phone maker put there (29 Sep): only their APK files, for check_installed -
   *  their permissions are not judged (a system app holding SMS power is normal). */
  @Suppress("DEPRECATION")
  private fun systemApps(): JSArray {
    val arr = JSArray()
    for (ai in ctx.packageManager.getInstalledApplications(0)) {
      if ((ai.flags and ApplicationInfo.FLAG_SYSTEM) == 0) continue
      arr.put(JSObject().apply {
        put("pkg", ai.packageName)
        put("paths", JSArray().apply { ai.sourceDir?.let { put(it) }; ai.splitSourceDirs?.forEach { put(it) } })
      })
    }
    return arr
  }

  /** May Vigil read every file in shared storage, and where is it (phone + SD card)?
   *  Android 11+: only "All files access" (MANAGE_EXTERNAL_STORAGE) shows another app's
   *  Download/, WhatsApp documents, APKs; without it the answer is allowed=false, never a list. */
  @Command
  fun storage(invoke: Invoke) {
    val res = JSObject()
    val allowed = if (Build.VERSION.SDK_INT >= 30) Environment.isExternalStorageManager()
      else ctx.checkSelfPermission(android.Manifest.permission.READ_EXTERNAL_STORAGE) == PackageManager.PERMISSION_GRANTED
    res.put("allowed", allowed)
    res.put("sdk", Build.VERSION.SDK_INT)
    val vols = JSArray()
    try {
      val sm = ctx.getSystemService(Context.STORAGE_SERVICE) as StorageManager
      for (v in sm.storageVolumes) {
        if (v.state != Environment.MEDIA_MOUNTED && v.state != Environment.MEDIA_MOUNTED_READ_ONLY) continue
        val dir = if (Build.VERSION.SDK_INT >= 30) v.directory else null
        val path = dir?.absolutePath ?: (if (v.isPrimary) Environment.getExternalStorageDirectory().absolutePath else null) ?: continue
        vols.put(JSObject().apply { put("name", if (v.isPrimary) "Phone storage" else (v.getDescription(ctx) ?: "SD card")); put("path", path) })
      }
    } catch (e: Throwable) { }
    if (vols.length() == 0) vols.put(JSObject().apply { put("name", "Phone storage"); put("path", Environment.getExternalStorageDirectory().absolutePath) })
    res.put("volumes", vols)
    invoke.resolve(res)
  }

  /** Runs a read; a read Android refuses becomes null ("unreadable"), never a verdict. */
  private fun guard(read: () -> Any?): Any? = try { read() ?: JSONObject.NULL } catch (e: Throwable) { JSONObject.NULL }

  private fun label(pkg: String): String = try {
    val pm = ctx.packageManager
    pm.getApplicationLabel(pm.getApplicationInfo(pkg, 0)).toString()
  } catch (e: Throwable) { pkg }

  private fun isSystem(pkg: String): Boolean = try {
    (ctx.packageManager.getApplicationInfo(pkg, 0).flags and ApplicationInfo.FLAG_SYSTEM) != 0
  } catch (e: Throwable) { false }

  private fun appRef(pkg: String) = JSObject().apply {
    put("pkg", pkg); put("label", label(pkg)); put("system", isSystem(pkg))
  }

  private fun wifi(): JSObject {
    val cm = ctx.getSystemService(Context.CONNECTIVITY_SERVICE) as ConnectivityManager
    val caps = cm.getNetworkCapabilities(cm.activeNetwork)
    val onWifi = caps?.hasTransport(NetworkCapabilities.TRANSPORT_WIFI) == true
    var security: Int? = null
    if (onWifi && Build.VERSION.SDK_INT >= 31) {
      val info = caps?.transportInfo as? WifiInfo
      val t = info?.currentSecurityType
      if (t != null && t != WifiInfo.SECURITY_TYPE_UNKNOWN) security = t
    }
    return JSObject().apply { put("connected", onWifi); put("security", security ?: JSONObject.NULL) }
  }

  private fun opMode(op: String, uid: Int, pkg: String): String? = try {
    val ops = ctx.getSystemService(Context.APP_OPS_SERVICE) as AppOpsManager
    val mode = if (Build.VERSION.SDK_INT >= 29) ops.unsafeCheckOpNoThrow(op, uid, pkg)
      else @Suppress("DEPRECATION") ops.checkOpNoThrow(op, uid, pkg)
    when (mode) {
      AppOpsManager.MODE_ALLOWED -> "allowed"
      AppOpsManager.MODE_DEFAULT -> "default"
      else -> "denied"
    }
  } catch (e: Throwable) { null }

  @Suppress("DEPRECATION")
  private fun apps(): JSArray {
    val pm = ctx.packageManager
    val list: List<PackageInfo> = if (Build.VERSION.SDK_INT >= 33)
      pm.getInstalledPackages(PackageManager.PackageInfoFlags.of(PackageManager.GET_PERMISSIONS.toLong()))
    else pm.getInstalledPackages(PackageManager.GET_PERMISSIONS)
    val arr = JSArray()
    for (p in list) {
      val ai = p.applicationInfo ?: continue
      val system = (ai.flags and ApplicationInfo.FLAG_SYSTEM) != 0
      if (system || p.packageName == ctx.packageName) continue
      // Full names (android.permission.X): knowledge.js PERMISSIONS / DANGER_COMBOS use them.
      val granted = JSArray()
      val requested = p.requestedPermissions ?: emptyArray()
      val flags = p.requestedPermissionsFlags
      requested.forEachIndexed { i, name ->
        val on = flags != null && i < flags.size && (flags[i] and PackageInfo.REQUESTED_PERMISSION_GRANTED) != 0
        if (on) granted.put(name)
      }
      val wants = requested.toSet()
      // Screen control, notification reading and device admin are not requested: an app OFFERS
      // them as a service/receiver guarded by a BIND_* permission (same as the APK reader's "offers").
      // Asked per app, because services+receivers for every app at once can overflow Android's
      // 1 MB binder limit on a phone with many apps.
      val offers = JSArray()
      // Signing-certificate SHA-1s (uppercase hex), matched against the bundled stalkerware list
      // (src/stalkerware.js). Unreadable = null -> the page draws no verdict from certificates.
      var certs: JSArray? = null
      // 31 Oct 2026: a refused read used to send offers as [] = "offers nothing", which the page
      // turned into "no banking-Trojan powers". Unread now goes out as null.
      var offersRead = false
      try {
        val sigFlag = if (Build.VERSION.SDK_INT >= 28) PackageManager.GET_SIGNING_CERTIFICATES else @Suppress("DEPRECATION") PackageManager.GET_SIGNATURES
        val full = pm.getPackageInfo(p.packageName, PackageManager.GET_SERVICES or PackageManager.GET_RECEIVERS or sigFlag)
        ((full.services?.map { it.permission } ?: emptyList()) + (full.receivers?.map { it.permission } ?: emptyList()))
          .filterNotNull().filter { it.startsWith("android.permission.BIND_") }.distinct().forEach { offers.put(it) }
        offersRead = true
        val sigs = if (Build.VERSION.SDK_INT >= 28) {
          val si = full.signingInfo
          // History includes certificates the app rotated away from; multiple signers has no history.
          if (si == null) null else if (si.hasMultipleSigners()) si.apkContentsSigners else si.signingCertificateHistory
        } else @Suppress("DEPRECATION") full.signatures
        if (sigs != null) {
          val md = java.security.MessageDigest.getInstance("SHA-1")
          certs = JSArray().apply { sigs.forEach { s -> put(md.digest(s.toByteArray()).joinToString("") { "%02X".format(it) }) } }
        }
      } catch (e: Throwable) { }
      val installer = try {
        if (Build.VERSION.SDK_INT >= 30) pm.getInstallSourceInfo(p.packageName).installingPackageName
        else pm.getInstallerPackageName(p.packageName)
      } catch (e: Throwable) { null }
      arr.put(JSObject().apply {
        put("pkg", p.packageName)
        put("label", pm.getApplicationLabel(ai).toString())
        put("installer", installer ?: JSONObject.NULL)
        put("installed", p.firstInstallTime)
        // The app's own APK file(s), fingerprinted by check_installed against the known-malware
        // list (25 Sep). Readable by any app (it is how Android loads it); splits are separate files.
        put("paths", JSArray().apply { ai.sourceDir?.let { put(it) }; ai.splitSourceDirs?.forEach { put(it) } })
        put("granted", granted)
        put("offers", if (offersRead) offers else JSONObject.NULL)
        put("certs", certs ?: JSONObject.NULL)
        put("overlay", if ("android.permission.SYSTEM_ALERT_WINDOW" in wants) (opMode(AppOpsManager.OPSTR_SYSTEM_ALERT_WINDOW, ai.uid, p.packageName) ?: JSONObject.NULL) else JSONObject.NULL)
        put("installsApps", if ("android.permission.REQUEST_INSTALL_PACKAGES" in wants) (opMode("android:request_install_packages", ai.uid, p.packageName) ?: JSONObject.NULL) else JSONObject.NULL)
      })
    }
    return arr
  }

  // ---------------------------------------------------------------- Settings pages

  @Command
  fun openSettings(invoke: Invoke) {
    val args = invoke.parseArgs(SettingsArgs::class.java)
    val pkgUri = args.pkg?.let { Uri.parse("package:$it") }
    val action = when (args.page) {
      "security" -> Settings.ACTION_SECURITY_SETTINGS
      "lock" -> DevicePolicyManager.ACTION_SET_NEW_PASSWORD
      "accessibility" -> Settings.ACTION_ACCESSIBILITY_SETTINGS
      "notificationAccess" -> "android.settings.ACTION_NOTIFICATION_LISTENER_SETTINGS"
      "developer" -> Settings.ACTION_APPLICATION_DEVELOPMENT_SETTINGS
      "unknownSources" -> if (Build.VERSION.SDK_INT >= 26) Settings.ACTION_MANAGE_UNKNOWN_APP_SOURCES else Settings.ACTION_SECURITY_SETTINGS
      "overlay" -> Settings.ACTION_MANAGE_OVERLAY_PERMISSION
      "wifi" -> Settings.ACTION_WIFI_SETTINGS
      "privacy" -> if (Build.VERSION.SDK_INT >= 29) Settings.ACTION_PRIVACY_SETTINGS else Settings.ACTION_SECURITY_SETTINGS
      "defaultApps" -> Settings.ACTION_MANAGE_DEFAULT_APPS_SETTINGS
      "about" -> Settings.ACTION_DEVICE_INFO_SETTINGS
      "app" -> Settings.ACTION_APPLICATION_DETAILS_SETTINGS
      // Android's own "Do you want to uninstall this app?" box; the person presses OK.
      "uninstall" -> Intent.ACTION_DELETE
      "allFiles" -> if (Build.VERSION.SDK_INT >= 30) Settings.ACTION_MANAGE_APP_ALL_FILES_ACCESS_PERMISSION else Settings.ACTION_APPLICATION_DETAILS_SETTINGS
      else -> { invoke.reject("unknown settings page"); return }
    }
    val intent = Intent(action).addFlags(Intent.FLAG_ACTIVITY_NEW_TASK)
    if (args.page == "app" || args.page == "uninstall") {
      if (pkgUri == null) { invoke.reject("no app named"); return }
      intent.data = pkgUri
    }
    // Our own switch, not another app's: the page never names a package for this one.
    if (args.page == "allFiles") intent.data = Uri.parse("package:" + ctx.packageName)
    val res = JSObject()
    try {
      activity.startActivity(intent)
      res.put("opened", args.page)
    } catch (e: Exception) {
      // Some makers remove a page (or refuse the uninstall box); an app's own page has Uninstall
      // too, and the main Settings screen is always there.
      if (args.page == "uninstall" && pkgUri != null) {
        activity.startActivity(Intent(Settings.ACTION_APPLICATION_DETAILS_SETTINGS, pkgUri).addFlags(Intent.FLAG_ACTIVITY_NEW_TASK))
        res.put("opened", "app")
      } else {
        activity.startActivity(Intent(Settings.ACTION_SETTINGS).addFlags(Intent.FLAG_ACTIVITY_NEW_TASK))
        res.put("opened", "settings")
      }
    }
    invoke.resolve(res)
  }

  // ---------------------------------------------------------------- files and shares

  /** A picked or shared file arrives as content://. Copy it into our cache so Rust can read it. */
  @Command
  fun copyToCache(invoke: Invoke) = background(invoke) {
    val args = invoke.parseArgs(UriArgs::class.java)
    val uri = Uri.parse(args.uri)
    var name = "shared-file"
    ctx.contentResolver.query(uri, arrayOf(OpenableColumns.DISPLAY_NAME), null, null, null)?.use { c ->
      if (c.moveToFirst() && !c.isNull(0)) name = c.getString(0)
    }
    name = name.replace(Regex("[^A-Za-z0-9._ -]"), "_").take(120).ifBlank { "shared-file" }
    val dir = File(ctx.cacheDir, "picked")
    dir.deleteRecursively()
    dir.mkdirs()
    val dest = File(dir, name)
    val input = ctx.contentResolver.openInputStream(uri) ?: throw IllegalStateException("cannot open that file")
    input.use { i -> dest.outputStream().use { o -> i.copyTo(o) } }
    JSObject().apply { put("path", dest.absolutePath); put("name", name) }
  }

  /** Whatever was shared into Vigil since the page last asked. Asking clears it. */
  @Command
  fun takeShare(invoke: Invoke) {
    val res = JSObject()
    res.put("text", sharedText ?: JSONObject.NULL)
    res.put("file", sharedFile ?: JSONObject.NULL)
    sharedText = null
    sharedFile = null
    invoke.resolve(res)
  }

  /** Where Rust keeps the phishing list on the phone. */
  @Command
  fun dataDir(invoke: Invoke) {
    invoke.resolve(JSObject().apply { put("path", ctx.filesDir.absolutePath) })
  }

  // ---------------------------------------------------------------- network (fixed addresses only: pwned range, phishing list, MalwareBazaar, CIRCL hashlookup, Groq)

  private fun http(url: String, headers: Map<String, String>, timeoutMs: Int): HttpURLConnection {
    val c = URL(url).openConnection() as HttpURLConnection
    c.connectTimeout = timeoutMs
    c.readTimeout = timeoutMs
    c.setRequestProperty("User-Agent", "VirusVigil (personal security helper)")
    headers.forEach { (k, v) -> c.setRequestProperty(k, v) }
    return c
  }

  /** Have I Been Pwned range look-up: only 5 hex characters of the hash leave the phone. */
  @Command
  fun pwned(invoke: Invoke) = background(invoke) {
    val prefix = invoke.parseArgs(PrefixArgs::class.java).prefix
    val res = JSObject()
    if (!Regex("^[0-9A-F]{5}$").matches(prefix)) {
      res.put("ok", false); res.put("error", "bad prefix"); return@background res
    }
    var error: String? = null
    for (attempt in 1..3) {
      try {
        val c = http("https://api.pwnedpasswords.com/range/$prefix", mapOf("Add-Padding" to "true"), 20000)
        val body = c.inputStream.use { it.readBytes().toString(Charsets.UTF_8) }
        res.put("ok", true); res.put("error", JSONObject.NULL); res.put("body", body)
        return@background res
      } catch (e: Throwable) {
        error = e.message ?: e.javaClass.simpleName
        Thread.sleep(2000L * attempt)
      }
    }
    res.put("ok", false); res.put("error", error); res.put("body", JSONObject.NULL)
    res
  }

  /** Download the public phishing-domain list to a file Rust then checks and swaps in. */
  @Command
  fun downloadPhishList(invoke: Invoke) = background(invoke) {
    val a = invoke.parseArgs(DownloadArgs::class.java)
    val dest = File(a.dest)
    val filesDir = ctx.filesDir.canonicalFile
    if (!dest.canonicalPath.startsWith(filesDir.path)) throw IllegalArgumentException("outside the app's folder")
    dest.parentFile?.mkdirs()
    if (a.source == "certpl") {
      // CERT Polska's Warning List (2 Nov 2026). Its own Last-Modified header is the makers' date:
      // the file is rebuilt every few minutes. 0 = the server gave none = unknown (null).
      val c = http("https://hole.cert.pl/domains/v2/domains.txt", emptyMap(), 120000)
      val code = c.responseCode
      if (code != 200) throw IllegalStateException("the list server answered HTTP $code")
      c.inputStream.use { i -> dest.outputStream().use { o -> i.copyTo(o) } }
      val lm = c.lastModified
      val upstream = if (lm > 0) java.text.SimpleDateFormat("yyyy-MM-dd'T'HH:mm:ss'Z'", java.util.Locale.US)
        .apply { timeZone = java.util.TimeZone.getTimeZone("UTC") }.format(java.util.Date(lm)) else null
      return@background JSObject().apply { put("path", dest.absolutePath); put("bytes", dest.length()); put("upstream", upstream ?: JSONObject.NULL) }
    }
    if (a.source != "pdb") throw IllegalArgumentException("unknown list: ${a.source}")
    val c = http("https://raw.githubusercontent.com/Phishing-Database/Phishing.Database/master/phishing-domains-ACTIVE.txt", emptyMap(), 120000)
    c.inputStream.use { i -> dest.outputStream().use { o -> i.copyTo(o) } }
    // When the list's makers last changed it (31 Oct 2026: it stopped on 2 Oct while our own
    // download time said "today"). Public GitHub record; nothing about the phone is sent. Null = unknown.
    val upstream = try {
      val a = http("https://api.github.com/repos/Phishing-Database/Phishing.Database/commits?path=phishing-domains-ACTIVE.txt&per_page=1",
        mapOf("Accept" to "application/vnd.github+json"), 30000)
      val body = a.inputStream.use { it.readBytes().toString(Charsets.UTF_8) }
      Regex("\"date\"\\s*:\\s*\"([0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}Z)\"").find(body)?.groupValues?.get(1)
    } catch (e: Throwable) { null }
    JSObject().apply { put("path", dest.absolutePath); put("bytes", dest.length()); put("upstream", upstream ?: JSONObject.NULL) }
  }

  /** MalwareBazaar's public list of known malware fingerprints, to a file Rust then checks and
   *  swaps in. `full` = every sample (a 43 MB zip holding one text file) - never taken over
   *  mobile data: on a metered network this answers {metered:true} and downloads nothing.
   *  Otherwise the last 48 hours (small plain text). Nothing about the phone is sent. */
  @Command
  fun downloadHashList(invoke: Invoke) = background(invoke) {
    val a = invoke.parseArgs(HashListArgs::class.java)
    val dest = File(a.dest)
    val filesDir = ctx.filesDir.canonicalFile
    if (!dest.canonicalPath.startsWith(filesDir.path)) throw IllegalArgumentException("outside the app's folder")
    dest.parentFile?.mkdirs()
    val cm = ctx.getSystemService(Context.CONNECTIVITY_SERVICE) as ConnectivityManager
    if (a.full && cm.isActiveNetworkMetered) {
      return@background JSObject().apply { put("metered", true) }
    }
    // Since Oct 2026 abuse.ch serves these only with an Auth-Key; keyless answers 410 Gone.
    val url = if (Regex("^[A-Za-z0-9]{20,100}$").matches(a.key)) {
      "https://mb-api.abuse.ch/v2/files/exports/${a.key}/" + (if (a.full) "sha256_full.txt.zip" else "sha256_recent.txt")
    } else {
      "https://bazaar.abuse.ch/export/txt/sha256/" + (if (a.full) "full/" else "recent/")
    }
    val c = http(url, emptyMap(), 600000)
    val code = c.responseCode
    if (code != 200) {
      throw IllegalStateException(
        if (code == 410 && a.key.isEmpty()) "the list server says 410 Gone - abuse.ch now needs a free Auth-Key"
        else "the list server answered HTTP $code")
    }
    c.inputStream.use { i ->
      if (!a.full) {
        dest.outputStream().use { o -> i.copyTo(o) }
      } else {
        java.util.zip.ZipInputStream(i).use { z ->
          var files = 0
          var e = z.nextEntry
          while (e != null) {
            if (!e.isDirectory) {
              files++
              if (files > 1) throw IllegalStateException("the zip held more than one file")
              dest.outputStream().use { o -> z.copyTo(o) }
            }
            e = z.nextEntry
          }
          if (files == 0) throw IllegalStateException("the zip held no file")
        }
      }
    }
    JSObject().apply { put("path", dest.absolutePath); put("bytes", dest.length()); put("metered", false) }
  }

  /** Online fingerprint look-up (his tap 29 Sep 2026: "Yes, fingerprints only"). Each SHA-256
   *  fingerprint (checked again here: 64 lowercase hex) is asked of CIRCL hashlookup, 8 at a time.
   *  Only the fingerprint leaves - never the file, its name or its path. Rust judges the replies.
   *  Every fingerprint gets a row {sha, status, body}; status 0 = no answer, body = the reason.
   *  If a whole first batch gets no answer at all, the rest are not tried. */
  @Command
  fun hashLookup(invoke: Invoke) = background(invoke) {
    val shas = invoke.parseArgs(HashesArgs::class.java).hashes.filter { Regex("^[0-9a-f]{64}$").matches(it) }.distinct()
    val rows = JSArray()
    val pool = java.util.concurrent.Executors.newFixedThreadPool(8)
    var dead = false
    try {
      for ((bi, batch) in shas.chunked(8).withIndex()) {
        if (dead) {
          batch.forEach { s -> rows.put(JSObject().apply { put("sha", s); put("status", 0); put("body", "not tried: the checker could not be reached") }) }
          continue
        }
        val jobs = batch.map { s ->
          pool.submit(java.util.concurrent.Callable {
            try {
              val c = http("https://hashlookup.circl.lu/lookup/sha256/$s", emptyMap(), 15000)
              val code = c.responseCode
              val body = (if (code in 200..299) c.inputStream else c.errorStream)?.use { it.readBytes().toString(Charsets.UTF_8) } ?: ""
              Triple(s, code, body)
            } catch (e: Throwable) {
              Triple(s, 0, e.message ?: e.javaClass.simpleName)
            }
          })
        }
        val got = jobs.map { it.get() }
        got.forEach { (s, code, body) -> rows.put(JSObject().apply { put("sha", s); put("status", code); put("body", body) }) }
        if (bi == 0 && got.all { it.second == 0 }) dead = true
      }
    } finally {
      pool.shutdownNow()
    }
    JSObject().apply { put("rows", rows) }
  }

  /** The online AI (Groq). Rust already stripped personal details and built the whole request
   *  body; this only posts it to the one fixed address and hands back status + raw reply. */
  @Command
  fun askOnline(invoke: Invoke) = background(invoke) {
    val a = invoke.parseArgs(OnlineArgs::class.java)
    val res = JSObject()
    try {
      val c = http("https://api.groq.com/openai/v1/chat/completions",
        mapOf("Authorization" to "Bearer ${a.key}", "Content-Type" to "application/json; charset=utf-8"), 45000)
      c.requestMethod = "POST"
      c.doOutput = true
      c.outputStream.use { it.write(a.body.toByteArray(Charsets.UTF_8)) }
      val status = c.responseCode
      val stream = if (status in 200..299) c.inputStream else c.errorStream
      res.put("status", status)
      res.put("body", stream?.use { it.readBytes().toString(Charsets.UTF_8) } ?: "")
      res.put("error", JSONObject.NULL)
    } catch (e: Throwable) {
      res.put("status", 0); res.put("body", ""); res.put("error", e.message ?: e.javaClass.simpleName)
    }
    res
  }
}
