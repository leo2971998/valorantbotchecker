import {
    fetch,
    parseSetCookie,
    stringifyCookies,
    extractTokensFromUri,
    tokenExpiry,
    decodeToken,
    ensureUsersFolder, wait, getProxyManager
} from "../misc/util.js";
import config from "../misc/config.js";
import fs from "fs";
import {client} from "../discord/bot.js";
import {addUser, deleteUser, getAccountWithPuuid, getUserJson, readUserJson, saveUser} from "./accountSwitcher.js";
import {checkRateLimit, isRateLimited} from "../misc/rateLimit.js";
import {queueCookiesLogin, queueUsernamePasswordLogin} from "./authQueue.js";
import {waitForAuthQueueResponse} from "../discord/authManager.js";

export class User {
    constructor({id, puuid, auth, alerts=[], username, region, authFailures, lastFetchedData, lastNoticeSeen, lastSawEasterEgg}) {
        this.id = id;
        this.puuid = puuid;
        this.auth = auth;
        this.alerts = alerts || [];
        this.username = username;
        this.region = region;
        this.authFailures = authFailures || 0;
        this.lastFetchedData = lastFetchedData || 0;
        this.lastNoticeSeen =  lastNoticeSeen || "";
        this.lastSawEasterEgg = lastSawEasterEgg || 0;
    }
}

export const transferUserDataFromOldUsersJson = () => {
    if (!fs.existsSync("data/users.json")) return;
    if (client.shard && client.shard.ids[0] !== 0) return;

    console.log("Transferring user data from users.json to the new format...");
    console.log("(The users.json file will be backed up as users.json.old, just in case)");

    const usersJson = JSON.parse(fs.readFileSync("data/users.json", "utf-8"));

    const alertsArray = fs.existsSync("data/alerts.json") ? JSON.parse(fs.readFileSync("data/alerts.json", "utf-8")) : [];
    const alertsForUser = (id) => alertsArray.filter(a => a.id === id);

    for (const id in usersJson) {
        const userData = usersJson[id];
        const user = new User({
            id: id,
            puuid: userData.puuid,
            auth: {
                rso: userData.rso,
                idt: userData.idt,
                ent: userData.ent,
                cookies: userData.cookies,
            },
            alerts: alertsForUser(id).map(alert => {return {uuid: alert.uuid, channel_id: alert.channel_id}}),
            username: userData.username,
            region: userData.region
        });
        saveUser(user);
    }
    fs.renameSync("data/users.json", "data/users.json.old");
}

export const getUser = (id, account=null) => {
    if (id instanceof User) {
        const user = id;
        const userJson = readUserJson(user.id);
        if (!userJson) return null;

        const userData = userJson.accounts.find(a => a.puuid === user.puuid);
        return userData && new User(userData);
    }

    try {
        const userData = getUserJson(id, account);
        return userData && new User(userData);
    } catch (e) {
        return null;
    }
}

const userFilenameRegex = /\d+\.json/
export const getUserList = () => {
    ensureUsersFolder();
    return fs.readdirSync("data/users").filter(filename => userFilenameRegex.test(filename)).map(filename => filename.replace(".json", ""));
}

export const authUser = async (id, account=null) => {
    const user = getUser(id, account);
    if (!user || !user.auth || !user.auth.rso) return {success: false};

    const rsoExpiry = tokenExpiry(user.auth.rso);
    if (rsoExpiry - Date.now() > 10_000) return {success: true};

    return await refreshToken(id, account);
}

export const redeemUsernamePassword = async (id, login, password) => {
    let rateLimit = isRateLimited("auth.riotgames.com");
    if (rateLimit) return {success: false, rateLimit: rateLimit};

    const proxyManager = getProxyManager();
    const proxy = await proxyManager.getProxy("auth.riotgames.com");
    const agent = await proxy?.createAgent("auth.riotgames.com");

    const req1 = await fetch("https://auth.riotgames.com/api/v1/authorization", {
        method: "POST",
        headers: {
            'Content-Type': 'application/json',
            'user-agent': await getUserAgent(),
        },
        body: JSON.stringify({
            "client_id": "riot-client",
            "redirect_uri": "http://localhost/redirect",
            "response_type": "code",
            "scope": "openid link ban lol_region"
        }),
        proxy: agent
    });
    if (req1.statusCode !== 200) {
        console.error("Error in auth request, status:", req1.statusCode);
        return {success: false};
    }

    rateLimit = checkRateLimit(req1, "auth.riotgames.com");
    if (rateLimit) return {success: false, rateLimit: rateLimit};

    let cookies = parseSetCookie(req1.headers["set-cookie"]);

    const authResponse = await req1.json();
    const code = authResponse.code;

    const req2 = await fetch("https://auth.riotgames.com/token", {
        method: "POST",
        headers: {
            'Content-Type': 'application/x-www-form-urlencoded',
            'Authorization': `Basic ${btoa(clientID + ":" + clientSecret)}`,
        },
        body: new URLSearchParams({
            'grant_type': 'authorization_code',
            'code': code,
            'redirect_uri': 'http://localhost/redirect',
        }),
        proxy: agent
    });

    if (req2.statusCode !== 200) {
        console.error("Error in token exchange, status:", req2.statusCode);
        return {success: false};
    }

    rateLimit = checkRateLimit(req2, "auth.riotgames.com")
    if (rateLimit) return {success: false, rateLimit: rateLimit};

    cookies = {
        ...cookies,
        ...parseSetCookie(req2.headers['set-cookie'])
    };

    const json2 = await req2.json();
    if (json2.type === 'error') {
        console.error("Authentication failure!", json2);
        return {success: false};
    }

    const user = await processAuthResponse(id, {login, password, cookies}, json2.response.parameters.uri);
    addUser(user);
    return {success: true};
}

const processAuthResponse = async (id, authData, redirect, user=null) => {
    if (!user) user = new User({id});
    const [rso, idt] = extractTokensFromUri(redirect);
    if (rso == null) {
        console.error("Riot servers didn't return an RSO token!");
        throw "Riot servers didn't return an RSO token!";
    }

    user.auth = {
        ...user.auth,
        rso: rso,
        idt: idt,
    }

    if (authData.login && config.storePasswords && !user.auth.waiting2FA) {
        user.auth.login = authData.login;
        user.auth.password = btoa(authData.password);
        delete user.auth.cookies;
    } else {
        user.auth.cookies = authData.cookies;
        delete user.auth.login;
        delete user.auth.password;
    }

    user.puuid = decodeToken(rso).sub;

    const existingAccount = getAccountWithPuuid(id, user.puuid);
    if (existingAccount) {
        user.username = existingAccount.username;
        user.region = existingAccount.region;
        if (existingAccount.auth) user.auth.ent = existingAccount.auth.ent;
    }

    const userInfo = await getUserInfo(user);
    user.username = userInfo.username;

    if (!user.auth.ent) user.auth.ent = await getEntitlements(user);

    if (!user.region) user.region = await getRegion(user);

    user.lastFetchedData = Date.now();

    user.authFailures = 0;
    return user;
}

const getUserAgent = async () => {
    return "ShooterGame/13 Windows/10.0.19043.1.256.64bit";
}

const detectCloudflareBlock = (req) => {
    return req.statusCode === 403 && req.headers["x-frame-options"] === "SAMEORIGIN";
}

export const deleteUserAuth = (user) => {
    user.auth = null;
    saveUser(user);
}
