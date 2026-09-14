package ru.moon.checker.checks;

import ru.moon.checker.core.Category;
import ru.moon.checker.core.CheckModule;
import ru.moon.checker.core.Finding;
import ru.moon.checker.core.I18n;
import ru.moon.checker.core.Platform;
import ru.moon.checker.core.ScanContext;
import ru.moon.checker.core.Severity;
import ru.moon.checker.parse.Vdf;
import ru.moon.checker.win.Registry;

import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.file.Files;
import java.nio.file.Path;
import java.time.Duration;
import java.util.List;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * Enumerates every Steam account that has logged in on this PC (from
 * {@code config/loginusers.vdf}) and looks up each one's public VAC-ban status
 * — no API key needed, via the community profile XML endpoint. Multiple
 * accounts hint at alts / ban evasion; a VAC-banned account tied to the machine
 * is important context for the admin.
 */
public final class SteamAccountsCheck implements CheckModule {

    public static final String ID = "steam";

    private static final Pattern VAC = Pattern.compile("<vacBanned>(\\d)</vacBanned>");
    private static final Pattern NAME = Pattern.compile("<steamID><!\\[CDATA\\[(.*?)]]></steamID>");

    @Override
    public String id() {
        return ID;
    }

    @Override
    public String displayName() {
        return I18n.t("module.steam");
    }

    @Override
    public Category category() {
        return Category.STEAM;
    }

    @Override
    public boolean windowsOnly() {
        return false; // Steam + VAC lookup works on Windows and Linux
    }

    @Override
    public void run(ScanContext ctx) {
        Path vdf = locateLoginUsers();
        if (vdf == null || !Files.isRegularFile(vdf)) {
            ctx.log(I18n.t("log.steam.none"));
            return;
        }
        List<Vdf.SteamAccount> accounts;
        try {
            accounts = Vdf.parseLoginUsers(Files.readString(vdf));
        } catch (Exception e) {
            return;
        }
        if (accounts.isEmpty()) {
            return;
        }

        if (accounts.size() > 1) {
            ctx.emit(Finding.builder(Category.STEAM, Severity.LOW,
                            "Несколько Steam-аккаунтов на ПК / Multiple Steam accounts on PC")
                    .module(ID)
                    .detail(accounts.size() + " accounts have logged in on this machine")
                    .source("loginusers.vdf")
                    .openPath(vdf.getParent().toString())
                    .build());
        }

        HttpClient http = HttpClient.newBuilder()
                .connectTimeout(Duration.ofSeconds(5)).build();

        for (Vdf.SteamAccount acc : accounts) {
            if (ctx.isCancelled()) {
                return;
            }
            ctx.log(I18n.t("log.steam", acc.accountName() == null ? acc.steamId64() : acc.accountName()));
            VacResult vac = lookupVac(http, acc.steamId64());
            Severity sev = vac.banned ? Severity.HIGH : Severity.INFO;
            String title = vac.banned
                    ? "VAC-бан на аккаунте / VAC-banned account on this PC"
                    : "Steam-аккаунт на ПК / Steam account on this PC";
            String detail = "id64=" + acc.steamId64()
                    + (acc.accountName() != null ? ", login=" + acc.accountName() : "")
                    + (acc.personaName() != null ? ", nick=" + acc.personaName() : "")
                    + (vac.checked ? (vac.banned ? "  — VAC BANNED" : "  — no VAC ban") : "  — статус не проверен");
            ctx.emit(Finding.builder(Category.STEAM, sev, title)
                    .module(ID)
                    .detail(detail)
                    .evidence("https://steamcommunity.com/profiles/" + acc.steamId64())
                    .source("Steam + VAC lookup")
                    .build());
        }
    }

    private record VacResult(boolean checked, boolean banned, String name) {
    }

    private VacResult lookupVac(HttpClient http, String steamId64) {
        try {
            HttpRequest req = HttpRequest.newBuilder()
                    .uri(URI.create("https://steamcommunity.com/profiles/" + steamId64 + "?xml=1"))
                    .timeout(Duration.ofSeconds(6))
                    .header("User-Agent", "MoonChecker/1.0")
                    .GET().build();
            HttpResponse<String> resp = http.send(req, HttpResponse.BodyHandlers.ofString());
            if (resp.statusCode() != 200) {
                return new VacResult(false, false, null);
            }
            String body = resp.body();
            Matcher vm = VAC.matcher(body);
            boolean banned = vm.find() && "1".equals(vm.group(1));
            Matcher nm = NAME.matcher(body);
            String name = nm.find() ? nm.group(1) : null;
            return new VacResult(true, banned, name);
        } catch (Exception e) {
            return new VacResult(false, false, null);
        }
    }

    private Path locateLoginUsers() {
        if (ru.moon.checker.core.Platform.isWindows()) {
            String steamPath = Registry.getString(Registry.HKCU, "Software\\Valve\\Steam", "SteamPath");
            if (steamPath != null) {
                Path p = Path.of(steamPath.replace('/', '\\'), "config", "loginusers.vdf");
                if (Files.isRegularFile(p)) {
                    return p;
                }
            }
            for (String base : new String[]{System.getenv("ProgramFiles(x86)"), System.getenv("ProgramFiles")}) {
                if (base == null) {
                    continue;
                }
                Path p = Path.of(base, "Steam", "config", "loginusers.vdf");
                if (Files.isRegularFile(p)) {
                    return p;
                }
            }
            return null;
        }
        // Linux: Steam lives under the user's home in a few known layouts
        for (Path home : ru.moon.checker.core.Platform.userProfiles()) {
            for (String rel : new String[]{
                    ".steam/steam/config/loginusers.vdf",
                    ".local/share/Steam/config/loginusers.vdf",
                    ".steam/root/config/loginusers.vdf",
                    ".var/app/com.valvesoftware.Steam/data/Steam/config/loginusers.vdf"}) {
                Path p = home.resolve(rel);
                if (Files.isRegularFile(p)) {
                    return p;
                }
            }
        }
        return null;
    }
}
