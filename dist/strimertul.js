const b64alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
const b64array = [
    ...b64alphabet
];
function base64ToBytesArr(str) {
    const result = [];
    for(let i = 0; i < str.length / 4; i++){
        const chunk = [
            ...str.slice(4 * i, 4 * i + 4)
        ];
        const bin = chunk.map((x)=>b64array.indexOf(x).toString(2).padStart(6, "0")).join("");
        const bytes = bin.match(/.{1,8}/g).map((x)=>+("0b" + x));
        result.push(...bytes.slice(0, 3 - (str[4 * i + 2] == "=" ? 1 : 0) - (str[4 * i + 3] == "=" ? 1 : 0)));
    }
    return result;
}
function bytesArrToBase64(arr) {
    const bin = (n)=>n.toString(2).padStart(8, "0");
    const l = arr.length;
    let result = "";
    for(let i = 0; i <= (l - 1) / 3; i++){
        const c1 = i * 3 + 1 >= l;
        const c2 = i * 3 + 2 >= l;
        const chunk = bin(arr[3 * i]) + bin(c1 ? 0 : arr[3 * i + 1]) + bin(c2 ? 0 : arr[3 * i + 2]);
        const r = chunk.match(/.{1,6}/g).map((x, j)=>j == 3 && c2 ? "=" : j == 2 && c1 ? "=" : b64alphabet[+("0b" + x)]);
        result += r.join("");
    }
    return result;
}
class EventEmitter extends EventTarget {
    on(eventName, listener) {
        return this.addEventListener(eventName, listener);
    }
    once(eventName, listener) {
        return this.addEventListener(eventName, listener, {
            once: true
        });
    }
    off(eventName, listener) {
        return this.removeEventListener(eventName, listener);
    }
    fire(eventName, detail) {
        return this.dispatchEvent(new CustomEvent(eventName, {
            detail,
            cancelable: true
        }));
    }
}
function generateRid() {
    return Math.random().toString(32);
}
async function authChallenge(password, challenge, salt) {
    const enc = new TextEncoder();
    const keyBytes = enc.encode(password);
    const saltBytes = base64ToBytesArr(salt);
    const challengeKey = Uint8Array.from([
        ...keyBytes,
        ...saltBytes
    ]);
    const challengeBytes = base64ToBytesArr(challenge);
    const key = await crypto.subtle.importKey("raw", challengeKey, {
        name: "HMAC",
        hash: {
            name: "SHA-256"
        }
    }, false, [
        "sign",
        "verify"
    ]);
    const signature = await crypto.subtle.sign("HMAC", key, Uint8Array.from(challengeBytes));
    return bytesArrToBase64(Array.from(new Uint8Array(signature)));
}
class Kilovolt extends EventEmitter {
    socket;
    address;
    options;
    pending;
    keySubscriptions;
    prefixSubscriptions;
    constructor(address = "ws://localhost:4337/ws", options){
        super();
        this.address = address;
        this.pending = {};
        this.keySubscriptions = {};
        this.prefixSubscriptions = {};
        this.options = options || {
            reconnect: true
        };
    }
    reconnect() {
        this.connect();
    }
    close() {
        this.options.reconnect = false;
        this.socket.close();
    }
    async connect() {
        this.socket = new WebSocket(this.address);
        this.socket.addEventListener("open", this.open.bind(this));
        this.socket.addEventListener("message", this.received.bind(this));
        this.socket.addEventListener("close", this.closed.bind(this));
        this.socket.addEventListener("error", this.errored.bind(this));
        await this.wait();
    }
    wait() {
        return new Promise((resolve)=>{
            if (this.socket.readyState === this.socket.OPEN) {
                resolve();
                return;
            }
            this.once("open", ()=>resolve());
        });
    }
    async open() {
        console.info("connected to server");
        if (this.options.password) {
            try {
                await this.authWithPassword(this.options.password);
            } catch (e) {
                this.fire("error", e);
                this.close();
            }
        } else if (this.options.interactive) {
            try {
                await this.authInteractive(this.options.interactiveData ?? {});
            } catch (e) {
                this.fire("error", e);
                this.close();
            }
        }
        this.resubscribe();
        this.fire("open");
        this.fire("stateChange", this.socket.readyState);
    }
    closed(ev) {
        console.warn(`lost connection to server: ${ev.reason}`);
        this.fire("close", ev);
        this.fire("stateChange", this.socket.readyState);
        if (this.options.reconnect) {
            setTimeout(()=>this.reconnect(), 5000);
        }
    }
    errored(ev) {
        this.fire("error", ev);
    }
    received(event) {
        const events = event.data.split("\n").map((ev)=>ev.trim()).filter((ev)=>ev.length > 0);
        events.forEach((ev)=>{
            const response = JSON.parse(ev ?? '""');
            if ("error" in response) {
                this.fire("error", response);
                if ("request_id" in response && response.request_id in this.pending) {
                    this.pending[response.request_id](response);
                    delete this.pending[response.request_id];
                }
                return;
            }
            switch(response.type){
                case "response":
                    if (response.request_id in this.pending) {
                        this.pending[response.request_id](response);
                        delete this.pending[response.request_id];
                    } else {
                        console.warn("Received a response for an unregistered request: ", response);
                    }
                    break;
                case "push":
                    {
                        if (response.key in this.keySubscriptions) {
                            this.keySubscriptions[response.key].forEach((fn)=>fn(response.new_value, response.key));
                        }
                        Object.entries(this.prefixSubscriptions).filter(([k])=>response.key.startsWith(k)).forEach(([_, subscribers])=>{
                            subscribers.forEach((fn)=>fn(response.new_value, response.key));
                        });
                        break;
                    }
                default:
            }
        });
    }
    async authWithPassword(password) {
        const request = await this.send({
            command: "klogin",
            data: {
                auth: "challenge"
            }
        });
        if ("error" in request) {
            console.error("kilovolt auth error:", request.error);
            throw new Error(request.error);
        }
        const hash = await authChallenge(password ?? "", request.data.challenge, request.data.salt);
        const response = await this.send({
            command: "kauth",
            data: {
                hash
            }
        });
        if ("error" in response) {
            console.error("kilovolt auth error:", response.error);
            throw new Error(response.error);
        }
    }
    async authInteractive(data) {
        const request = await this.send({
            command: "klogin",
            data: {
                ...data,
                auth: "ask"
            }
        });
        if ("error" in request) {
            console.error("kilovolt auth error:", request.error);
            throw new Error(request.error);
        }
    }
    async resubscribe() {
        for(const key in this.keySubscriptions){
            await this.send({
                command: "ksub",
                data: {
                    key
                }
            });
        }
        for(const prefix in this.prefixSubscriptions){
            this.send({
                command: "ksub-prefix",
                data: {
                    prefix
                }
            });
        }
    }
    send(msg) {
        if (this.socket.readyState !== this.socket.OPEN) {
            throw new Error("Not connected to server");
        }
        const message = {
            ...msg,
            request_id: "request_id" in msg ? msg.request_id : generateRid()
        };
        return new Promise((resolve)=>{
            const payload = JSON.stringify(message);
            this.socket.send(payload);
            this.pending[message.request_id] = resolve;
        });
    }
    putKey(key, data) {
        return this.send({
            command: "kset",
            data: {
                key,
                data
            }
        });
    }
    putKeys(data) {
        return this.send({
            command: "kset-bulk",
            data
        });
    }
    putJSON(key, data) {
        return this.send({
            command: "kset",
            data: {
                key,
                data: JSON.stringify(data)
            }
        });
    }
    putJSONs(data) {
        const jsonData = {};
        Object.entries(data).forEach(([k, v])=>{
            jsonData[k] = JSON.stringify(v);
        });
        return this.send({
            command: "kset-bulk",
            data: jsonData
        });
    }
    async getKey(key) {
        const response = await this.send({
            command: "kget",
            data: {
                key
            }
        });
        if ("error" in response) {
            throw new Error(response.error);
        }
        return response.data;
    }
    async getKeys(keys) {
        const response = await this.send({
            command: "kget-bulk",
            data: {
                keys
            }
        });
        if ("error" in response) {
            throw new Error(response.error);
        }
        return response.data;
    }
    async getKeysByPrefix(prefix) {
        const response = await this.send({
            command: "kget-all",
            data: {
                prefix
            }
        });
        if ("error" in response) {
            throw new Error(response.error);
        }
        return response.data;
    }
    async getJSON(key) {
        const response = await this.send({
            command: "kget",
            data: {
                key
            }
        });
        if ("error" in response) {
            throw new Error(response.error);
        }
        return JSON.parse(response.data);
    }
    async getJSONs(keys) {
        const response = await this.send({
            command: "kget-bulk",
            data: {
                keys
            }
        });
        if ("error" in response) {
            throw new Error(response.error);
        }
        const returnData = {};
        Object.entries(response.data).forEach(([k, v])=>{
            returnData[k] = JSON.parse(v);
        });
        return returnData;
    }
    subscribeKey(key, fn) {
        if (key in this.keySubscriptions) {
            this.keySubscriptions[key].push(fn);
        } else {
            this.keySubscriptions[key] = [
                fn
            ];
        }
        return this.send({
            command: "ksub",
            data: {
                key
            }
        });
    }
    async unsubscribeKey(key, fn) {
        if (!(key in this.keySubscriptions)) {
            console.warn(`Trying to unsubscribe from key "${key}" but no subscriptions could be found!`);
            return false;
        }
        const index = this.keySubscriptions[key].findIndex((subfn)=>subfn === fn);
        if (index < 0) {
            console.warn(`Trying to unsubscribe from key "${key}" but specified function is not in the subscribers!`);
            return false;
        }
        this.keySubscriptions[key].splice(index, 1);
        if (this.keySubscriptions[key].length < 1) {
            const res = await this.send({
                command: "kunsub",
                data: {
                    key
                }
            });
            if ("error" in res) {
                console.warn(`unsubscribe failed: ${res.error}`);
            }
            return res.ok;
        }
        return true;
    }
    subscribePrefix(prefix, fn) {
        if (prefix in this.keySubscriptions) {
            this.prefixSubscriptions[prefix].push(fn);
        } else {
            this.prefixSubscriptions[prefix] = [
                fn
            ];
        }
        return this.send({
            command: "ksub-prefix",
            data: {
                prefix
            }
        });
    }
    async unsubscribePrefix(prefix, fn) {
        if (!(prefix in this.prefixSubscriptions)) {
            console.warn(`Trying to unsubscribe from prefix "${prefix}" but no subscriptions could be found!`);
            return false;
        }
        const index = this.prefixSubscriptions[prefix].findIndex((subfn)=>subfn === fn);
        if (index < 0) {
            console.warn(`Trying to unsubscribe from key "${prefix}" but specified function is not in the subscribers!`);
            return false;
        }
        this.prefixSubscriptions[prefix].splice(index, 1);
        if (this.prefixSubscriptions[prefix].length < 1) {
            const res = await this.send({
                command: "kunsub-prefix",
                data: {
                    prefix
                }
            });
            if ("error" in res) {
                console.warn(`unsubscribe failed: ${res.error}`);
            }
            return res.ok;
        }
        return true;
    }
    async keyList(prefix) {
        const response = await this.send({
            command: "klist",
            data: {
                prefix: prefix ?? ""
            }
        });
        if ("error" in response) {
            throw new Error(response.error);
        }
        return response.data;
    }
    async deleteKey(key) {
        const response = await this.send({
            command: "kdel",
            data: {
                key
            }
        });
        if ("error" in response) {
            throw new Error(response.error);
        }
        return response.data;
    }
}
class Chat {
    kv;
    constructor(kv){
        this.kv = kv;
    }
    onMessage(callback) {
        return this.kv.subscribeKey("twitch/ev/chat-message", (newValue)=>{
            const message = JSON.parse(newValue);
            callback(message);
        });
    }
    writeMessage(message) {
        return this.kv.putKey("twitch/@send-chat-message", message);
    }
}
class EventSub {
    kv;
    constructor(kv){
        this.kv = kv;
    }
    onEventSubEvent(callback) {
        return this.kv.subscribeKey("twitch/ev/eventsub-event", (newValue)=>{
            const ev = JSON.parse(newValue);
            callback(ev);
        });
    }
    onRedeem(callback) {
        return this.onEventSubEvent((ev)=>{
            if (ev.subscription.type !== "channel.channel_points_custom_reward_redemption.add") {
                return;
            }
            callback(ev);
        });
    }
    onNewFollow(callback) {
        return this.onEventSubEvent((ev)=>{
            if (ev.subscription.type !== "channel.follow") {
                return;
            }
            callback(ev);
        });
    }
    onNewSubscription(callback) {
        return this.onEventSubEvent((ev)=>{
            if (ev.subscription.type !== "channel.subscribe") {
                return;
            }
            callback(ev);
        });
    }
    onGiftedSubscription(callback) {
        return this.onEventSubEvent((ev)=>{
            if (ev.subscription.type !== "channel.subscription.gift") {
                return;
            }
            callback(ev);
        });
    }
    onResubscription(callback) {
        return this.onEventSubEvent((ev)=>{
            if (ev.subscription.type !== "channel.subscription.message") {
                return;
            }
            callback(ev);
        });
    }
    onChannelUpdate(callback) {
        return this.onEventSubEvent((ev)=>{
            if (ev.subscription.type !== "channel.update") {
                return;
            }
            callback(ev);
        });
    }
    onCheer(callback) {
        return this.onEventSubEvent((ev)=>{
            if (ev.subscription.type !== "channel.cheer") {
                return;
            }
            callback(ev);
        });
    }
    onRaid(callback) {
        return this.onEventSubEvent((ev)=>{
            if (ev.subscription.type !== "channel.raid") {
                return;
            }
            callback(ev);
        });
    }
}
class Twitch {
    chat;
    event;
    constructor(kv){
        this.chat = new Chat(kv);
        this.event = new EventSub(kv);
    }
}
class Loyalty {
    kv;
    onRedeem(callback) {
        return this.kv.subscribeKey("loyalty/ev/new-redeem", (newValue)=>{
            const message = JSON.parse(newValue);
            callback(message);
        });
    }
    constructor(kv){
        this.kv = kv;
    }
}
class Strimertul {
    kv;
    twitch;
    loyalty;
    constructor(options){
        this.kv = new Kilovolt(options.address || "ws://localhost:4337/ws", {
            reconnect: true,
            ...options
        });
        this.twitch = new Twitch(this.kv);
        this.loyalty = new Loyalty(this.kv);
    }
    connect() {
        return this.kv.connect();
    }
}
export { Strimertul as default };
//# sourceMappingURL=data:application/json;base64,eyJ2ZXJzaW9uIjozLCJzb3VyY2VzIjpbImh0dHBzOi8vZGVuby5sYW5kL3gva2lsb3ZvbHRAdjguMC4wL3V0aWxzLnRzIiwiaHR0cHM6Ly9kZW5vLmxhbmQveC9raWxvdm9sdEB2OC4wLjAvaW5kZXgudHMiLCJmaWxlOi8vL0M6L3Byb2plY3RzL3N0cmltZXJ0dWwvc3RyaW1lcnR1bC10cy9zcmMvdHdpdGNoL3R3aXRjaC50cyIsImZpbGU6Ly8vQzovcHJvamVjdHMvc3RyaW1lcnR1bC9zdHJpbWVydHVsLXRzL3NyYy9sb3lhbHR5L2xveWFsdHkudHMiLCJmaWxlOi8vL0M6L3Byb2plY3RzL3N0cmltZXJ0dWwvc3RyaW1lcnR1bC10cy9zcmMvc3RyaW1lcnR1bC50cyJdLCJzb3VyY2VzQ29udGVudCI6WyJjb25zdCBiNjRhbHBoYWJldCA9XG4gIFwiQUJDREVGR0hJSktMTU5PUFFSU1RVVldYWVphYmNkZWZnaGlqa2xtbm9wcXJzdHV2d3h5ejAxMjM0NTY3ODkrL1wiO1xuY29uc3QgYjY0YXJyYXkgPSBbLi4uYjY0YWxwaGFiZXRdO1xuXG4vLyBodHRwczovL3N0YWNrb3ZlcmZsb3cuY29tL2EvNjIzNjQ1MTlcbmV4cG9ydCBmdW5jdGlvbiBiYXNlNjRUb0J5dGVzQXJyKHN0cjogc3RyaW5nKSB7XG4gIGNvbnN0IHJlc3VsdCA9IFtdO1xuXG4gIGZvciAobGV0IGkgPSAwOyBpIDwgc3RyLmxlbmd0aCAvIDQ7IGkrKykge1xuICAgIGNvbnN0IGNodW5rID0gWy4uLnN0ci5zbGljZSg0ICogaSwgNCAqIGkgKyA0KV07XG4gICAgY29uc3QgYmluID0gY2h1bmtcbiAgICAgIC5tYXAoKHgpID0+IGI2NGFycmF5LmluZGV4T2YoeCkudG9TdHJpbmcoMikucGFkU3RhcnQoNiwgXCIwXCIpKVxuICAgICAgLmpvaW4oXCJcIik7XG4gICAgY29uc3QgYnl0ZXMgPSBiaW4ubWF0Y2goLy57MSw4fS9nKSEubWFwKCh4KSA9PiArKFwiMGJcIiArIHgpKTtcbiAgICByZXN1bHQucHVzaChcbiAgICAgIC4uLmJ5dGVzLnNsaWNlKFxuICAgICAgICAwLFxuICAgICAgICAzIC0gKHN0cls0ICogaSArIDJdID09IFwiPVwiID8gMSA6IDApIC0gKHN0cls0ICogaSArIDNdID09IFwiPVwiID8gMSA6IDApXG4gICAgICApXG4gICAgKTtcbiAgfVxuICByZXR1cm4gcmVzdWx0O1xufVxuXG5leHBvcnQgZnVuY3Rpb24gYnl0ZXNBcnJUb0Jhc2U2NChhcnI6IG51bWJlcltdKSB7XG4gIGNvbnN0IGJpbiA9IChuOiBudW1iZXIpID0+IG4udG9TdHJpbmcoMikucGFkU3RhcnQoOCwgXCIwXCIpOyAvLyBjb252ZXJ0IG51bSB0byA4LWJpdCBiaW5hcnkgc3RyaW5nXG4gIGNvbnN0IGwgPSBhcnIubGVuZ3RoO1xuICBsZXQgcmVzdWx0ID0gXCJcIjtcblxuICBmb3IgKGxldCBpID0gMDsgaSA8PSAobCAtIDEpIC8gMzsgaSsrKSB7XG4gICAgY29uc3QgYzEgPSBpICogMyArIDEgPj0gbDsgLy8gY2FzZSB3aGVuIFwiPVwiIGlzIG9uIGVuZFxuICAgIGNvbnN0IGMyID0gaSAqIDMgKyAyID49IGw7IC8vIGNhc2Ugd2hlbiBcIj1cIiBpcyBvbiBlbmRcbiAgICBjb25zdCBjaHVuayA9XG4gICAgICBiaW4oYXJyWzMgKiBpXSkgK1xuICAgICAgYmluKGMxID8gMCA6IGFyclszICogaSArIDFdKSArXG4gICAgICBiaW4oYzIgPyAwIDogYXJyWzMgKiBpICsgMl0pO1xuICAgIGNvbnN0IHIgPSBjaHVua1xuICAgICAgLm1hdGNoKC8uezEsNn0vZykhXG4gICAgICAubWFwKCh4LCBqKSA9PlxuICAgICAgICBqID09IDMgJiYgYzIgPyBcIj1cIiA6IGogPT0gMiAmJiBjMSA/IFwiPVwiIDogYjY0YWxwaGFiZXRbKyhcIjBiXCIgKyB4KV1cbiAgICAgICk7XG4gICAgcmVzdWx0ICs9IHIuam9pbihcIlwiKTtcbiAgfVxuXG4gIHJldHVybiByZXN1bHQ7XG59XG5cbmV4cG9ydCBjbGFzcyBFdmVudEVtaXR0ZXIgZXh0ZW5kcyBFdmVudFRhcmdldCB7XG4gIG9uKGV2ZW50TmFtZTogc3RyaW5nLCBsaXN0ZW5lcjogRXZlbnRMaXN0ZW5lck9yRXZlbnRMaXN0ZW5lck9iamVjdCkge1xuICAgIHJldHVybiB0aGlzLmFkZEV2ZW50TGlzdGVuZXIoZXZlbnROYW1lLCBsaXN0ZW5lcik7XG4gIH1cbiAgb25jZShldmVudE5hbWU6IHN0cmluZywgbGlzdGVuZXI6IEV2ZW50TGlzdGVuZXJPckV2ZW50TGlzdGVuZXJPYmplY3QpIHtcbiAgICByZXR1cm4gdGhpcy5hZGRFdmVudExpc3RlbmVyKGV2ZW50TmFtZSwgbGlzdGVuZXIsIHsgb25jZTogdHJ1ZSB9KTtcbiAgfVxuICBvZmYoZXZlbnROYW1lOiBzdHJpbmcsIGxpc3RlbmVyOiBFdmVudExpc3RlbmVyT3JFdmVudExpc3RlbmVyT2JqZWN0KSB7XG4gICAgcmV0dXJuIHRoaXMucmVtb3ZlRXZlbnRMaXN0ZW5lcihldmVudE5hbWUsIGxpc3RlbmVyKTtcbiAgfVxuICBwcm90ZWN0ZWQgZmlyZTxUPihldmVudE5hbWU6IHN0cmluZywgZGV0YWlsPzogVCkge1xuICAgIHJldHVybiB0aGlzLmRpc3BhdGNoRXZlbnQoXG4gICAgICBuZXcgQ3VzdG9tRXZlbnQoZXZlbnROYW1lLCB7IGRldGFpbCwgY2FuY2VsYWJsZTogdHJ1ZSB9KVxuICAgICk7XG4gIH1cbn1cbiIsImltcG9ydCB7IGJhc2U2NFRvQnl0ZXNBcnIsIGJ5dGVzQXJyVG9CYXNlNjQsIEV2ZW50RW1pdHRlciB9IGZyb20gXCIuL3V0aWxzLnRzXCI7XG5pbXBvcnQge1xuICBrdkdldCxcbiAga3ZHZXRCdWxrLFxuICBrdkdldEFsbCxcbiAga3ZTZXQsXG4gIGt2U2V0QnVsayxcbiAga3ZTdWJzY3JpYmVLZXksXG4gIGt2VW5zdWJzY3JpYmVLZXksXG4gIGt2U3Vic2NyaWJlUHJlZml4LFxuICBrdlVuc3Vic2NyaWJlUHJlZml4LFxuICBrdlZlcnNpb24sXG4gIGt2S2V5TGlzdCxcbiAga3ZMb2dpbixcbiAga3ZFcnJvcixcbiAga3ZQdXNoLFxuICBLaWxvdm9sdFJlc3BvbnNlLFxuICBrdkdlbmVyaWNSZXNwb25zZSxcbiAga3ZBdXRoLFxuICBrdkVtcHR5UmVzcG9uc2UsXG4gIGt2SW50ZXJuYWxDbGllbnRJRCxcbiAga3ZEZWxldGUsXG59IGZyb20gXCIuL21lc3NhZ2VzLnRzXCI7XG5cbmV4cG9ydCB0eXBlIFN1YnNjcmlwdGlvbkhhbmRsZXIgPSAobmV3VmFsdWU6IHN0cmluZywga2V5OiBzdHJpbmcpID0+IHZvaWQ7XG5cbmV4cG9ydCB0eXBlIEtpbG92b2x0UmVxdWVzdCA9XG4gIHwga3ZHZXRcbiAgfCBrdkdldEJ1bGtcbiAgfCBrdkdldEFsbFxuICB8IGt2U2V0XG4gIHwga3ZTZXRCdWxrXG4gIHwga3ZTdWJzY3JpYmVLZXlcbiAgfCBrdlVuc3Vic2NyaWJlS2V5XG4gIHwga3ZTdWJzY3JpYmVQcmVmaXhcbiAgfCBrdlVuc3Vic2NyaWJlUHJlZml4XG4gIHwga3ZWZXJzaW9uXG4gIHwga3ZLZXlMaXN0XG4gIHwga3ZEZWxldGVcbiAgfCBrdkxvZ2luXG4gIHwga3ZBdXRoXG4gIHwga3ZJbnRlcm5hbENsaWVudElEO1xuXG5leHBvcnQgdHlwZSBLaWxvdm9sdE1lc3NhZ2UgPSBrdkVycm9yIHwga3ZQdXNoIHwgS2lsb3ZvbHRSZXNwb25zZTtcblxuLyoqXG4gKiBTaW1wbGUgcmFuZG9tIGZ1bmN0aW9uIGZvciBnZW5lcmF0aW5nIHJlcXVlc3QgSURzXG4gKiBOb3RlOiBub3QgY3J5cHRvZ3JhcGhpY2FsbHkgc2VjdXJlIVxuICogQHJldHVybnMgUmFuZG9tIGhleCBzdHJpbmdcbiAqL1xuZnVuY3Rpb24gZ2VuZXJhdGVSaWQoKSB7XG4gIHJldHVybiBNYXRoLnJhbmRvbSgpLnRvU3RyaW5nKDMyKTtcbn1cblxuLyoqXG4gKiBDYWxjdWxhdGUgYW5kIGVuY29kZSB0aGUgaGFzaCBmb3IgYXV0aGVudGljYXRpb24gY2hhbGxlbmdlcyB1c2luZyBXZWIgQ3J5cHRvIEFQSVxuICogQHBhcmFtIHBhc3N3b3JkIFNoYXJlZCBrZXkgZm9yIGF1dGhlbnRpY2F0aW9uXG4gKiBAcGFyYW0gY2hhbGxlbmdlIEJhc2U2NCBvZiB0aGUgcmVjZWl2ZWQgY2hhbGxlbmdlXG4gKiBAcGFyYW0gc2FsdCBCYXNlNjQgb2YgdGhlIHJlY2VpdmVkIHNhbHRcbiAqIEByZXR1cm5zIEJhc2U2NCBlbmNvZGVkIGhhc2hcbiAqL1xuYXN5bmMgZnVuY3Rpb24gYXV0aENoYWxsZW5nZShcbiAgcGFzc3dvcmQ6IHN0cmluZyxcbiAgY2hhbGxlbmdlOiBzdHJpbmcsXG4gIHNhbHQ6IHN0cmluZ1xuKSB7XG4gIC8vIEVuY29kZSBwYXNzd29yZFxuICBjb25zdCBlbmMgPSBuZXcgVGV4dEVuY29kZXIoKTtcbiAgY29uc3Qga2V5Qnl0ZXMgPSBlbmMuZW5jb2RlKHBhc3N3b3JkKTtcbiAgY29uc3Qgc2FsdEJ5dGVzID0gYmFzZTY0VG9CeXRlc0FycihzYWx0KTtcbiAgY29uc3QgY2hhbGxlbmdlS2V5ID0gVWludDhBcnJheS5mcm9tKFsuLi5rZXlCeXRlcywgLi4uc2FsdEJ5dGVzXSk7XG4gIGNvbnN0IGNoYWxsZW5nZUJ5dGVzID0gYmFzZTY0VG9CeXRlc0FycihjaGFsbGVuZ2UpO1xuXG4gIGNvbnN0IGtleSA9IGF3YWl0IGNyeXB0by5zdWJ0bGUuaW1wb3J0S2V5KFxuICAgIFwicmF3XCIsXG4gICAgY2hhbGxlbmdlS2V5LFxuICAgIHsgbmFtZTogXCJITUFDXCIsIGhhc2g6IHsgbmFtZTogXCJTSEEtMjU2XCIgfSB9LFxuICAgIGZhbHNlLFxuICAgIFtcInNpZ25cIiwgXCJ2ZXJpZnlcIl1cbiAgKTtcbiAgY29uc3Qgc2lnbmF0dXJlID0gYXdhaXQgY3J5cHRvLnN1YnRsZS5zaWduKFxuICAgIFwiSE1BQ1wiLFxuICAgIGtleSxcbiAgICBVaW50OEFycmF5LmZyb20oY2hhbGxlbmdlQnl0ZXMpXG4gICk7XG4gIHJldHVybiBieXRlc0FyclRvQmFzZTY0KEFycmF5LmZyb20obmV3IFVpbnQ4QXJyYXkoc2lnbmF0dXJlKSkpO1xufVxuXG5pbnRlcmZhY2UgQ2xpZW50T3B0aW9ucyB7XG4gIC8qIElmIHRydWUsIHJlY29ubmVjdCB0byB0aGUgc2VydmVyIGlmIHRoZSBjb25uZWN0aW9uIGdldHMgdGVybWluYXRlZCBmb3IgYW55IHJlYXNvbiAqL1xuICByZWNvbm5lY3Q/OiBib29sZWFuO1xuXG4gIC8qIElmIHByb3ZpZGVkLCBhdXRoZW50aWNhdGUgbm9uLWludGVyYWN0aXZlbHkgYXMgc29vbiBhcyBjb25uZWN0aW9uIGlzIGVzdGFibGlzaGVkICovXG4gIHBhc3N3b3JkPzogc3RyaW5nO1xuXG4gIC8qIElmIHRydWUsIGF1dGhlbnRpY2F0ZSBpbnRlcmFjdGl2ZWx5IGFzIHNvb24gYXMgY29ubmVjdGlvbiBpcyBlc3RhYmxpc2hlZCAqL1xuICBpbnRlcmFjdGl2ZT86IGJvb2xlYW47XG5cbiAgLyogV2hlbiBhdXRoZW50aWNhdGluZyBpbnRlcmFjdGl2ZWx5LCB0aGlzIGRhdGEgaXMgYWRkZWQgdG8gdGhlIGF1dGggbWVzc2FnZSAqL1xuICBpbnRlcmFjdGl2ZURhdGE/OiBSZWNvcmQ8c3RyaW5nLCB1bmtub3duPjtcbn1cblxuZXhwb3J0IGNsYXNzIEtpbG92b2x0IGV4dGVuZHMgRXZlbnRFbWl0dGVyIHtcbiAgcHJpdmF0ZSBzb2NrZXQhOiBXZWJTb2NrZXQ7XG5cbiAgcHJpdmF0ZSBhZGRyZXNzOiBzdHJpbmc7XG4gIHByaXZhdGUgb3B0aW9uczogQ2xpZW50T3B0aW9ucztcblxuICBwcml2YXRlIHBlbmRpbmc6IFJlY29yZDxzdHJpbmcsIChyZXNwb25zZTogS2lsb3ZvbHRNZXNzYWdlKSA9PiB2b2lkPjtcblxuICBwcml2YXRlIGtleVN1YnNjcmlwdGlvbnM6IFJlY29yZDxzdHJpbmcsIFN1YnNjcmlwdGlvbkhhbmRsZXJbXT47XG4gIHByaXZhdGUgcHJlZml4U3Vic2NyaXB0aW9uczogUmVjb3JkPHN0cmluZywgU3Vic2NyaXB0aW9uSGFuZGxlcltdPjtcblxuICAvKipcbiAgICogQ3JlYXRlIGEgbmV3IEtpbG92b2x0IGNsaWVudCBpbnN0YW5jZSBhbmQgY29ubmVjdCB0byBpdFxuICAgKiBAcGFyYW0gYWRkcmVzcyBLaWxvdm9sdCBzZXJ2ZXIgZW5kcG9pbnQgKGluY2x1ZGluZyBwYXRoKVxuICAgKi9cbiAgY29uc3RydWN0b3IoYWRkcmVzcyA9IFwid3M6Ly9sb2NhbGhvc3Q6NDMzNy93c1wiLCBvcHRpb25zPzogQ2xpZW50T3B0aW9ucykge1xuICAgIHN1cGVyKCk7XG4gICAgdGhpcy5hZGRyZXNzID0gYWRkcmVzcztcbiAgICB0aGlzLnBlbmRpbmcgPSB7fTtcbiAgICB0aGlzLmtleVN1YnNjcmlwdGlvbnMgPSB7fTtcbiAgICB0aGlzLnByZWZpeFN1YnNjcmlwdGlvbnMgPSB7fTtcbiAgICB0aGlzLm9wdGlvbnMgPSBvcHRpb25zIHx8IHtcbiAgICAgIHJlY29ubmVjdDogdHJ1ZSxcbiAgICB9O1xuICB9XG5cbiAgLyoqXG4gICAqIFJlLWNvbm5lY3QgdG8ga2lsb3ZvbHQgc2VydmVyXG4gICAqL1xuICByZWNvbm5lY3QoKTogdm9pZCB7XG4gICAgdGhpcy5jb25uZWN0KCk7XG4gIH1cblxuICAvKipcbiAgICogQ2xvc2UgY29ubmVjdGlvbiB0byBzZXJ2ZXJcbiAgICovXG4gIGNsb3NlKCk6IHZvaWQge1xuICAgIHRoaXMub3B0aW9ucy5yZWNvbm5lY3QgPSBmYWxzZTtcbiAgICB0aGlzLnNvY2tldC5jbG9zZSgpO1xuICB9XG5cbiAgLyoqXG4gICAqIENvbm5lY3QgdG8gdGhlIEtpbG92b2x0IHNlcnZlclxuICAgKi9cbiAgYXN5bmMgY29ubmVjdCgpIHtcbiAgICB0aGlzLnNvY2tldCA9IG5ldyBXZWJTb2NrZXQodGhpcy5hZGRyZXNzKTtcbiAgICB0aGlzLnNvY2tldC5hZGRFdmVudExpc3RlbmVyKFwib3BlblwiLCB0aGlzLm9wZW4uYmluZCh0aGlzKSk7XG4gICAgdGhpcy5zb2NrZXQuYWRkRXZlbnRMaXN0ZW5lcihcIm1lc3NhZ2VcIiwgdGhpcy5yZWNlaXZlZC5iaW5kKHRoaXMpKTtcbiAgICB0aGlzLnNvY2tldC5hZGRFdmVudExpc3RlbmVyKFwiY2xvc2VcIiwgdGhpcy5jbG9zZWQuYmluZCh0aGlzKSk7XG4gICAgdGhpcy5zb2NrZXQuYWRkRXZlbnRMaXN0ZW5lcihcImVycm9yXCIsIHRoaXMuZXJyb3JlZC5iaW5kKHRoaXMpKTtcbiAgICBhd2FpdCB0aGlzLndhaXQoKTtcbiAgfVxuXG4gIC8qKlxuICAgKiBXYWl0IGZvciB3ZWJzb2NrZXQgY29ubmVjdGlvbiB0byBiZSBlc3RhYmxpc2hlZFxuICAgKi9cbiAgcHJpdmF0ZSB3YWl0KCk6IFByb21pc2U8dm9pZD4ge1xuICAgIHJldHVybiBuZXcgUHJvbWlzZSgocmVzb2x2ZSkgPT4ge1xuICAgICAgaWYgKHRoaXMuc29ja2V0LnJlYWR5U3RhdGUgPT09IHRoaXMuc29ja2V0Lk9QRU4pIHtcbiAgICAgICAgcmVzb2x2ZSgpO1xuICAgICAgICByZXR1cm47XG4gICAgICB9XG4gICAgICB0aGlzLm9uY2UoXCJvcGVuXCIsICgpID0+IHJlc29sdmUoKSk7XG4gICAgfSk7XG4gIH1cblxuICBwcml2YXRlIGFzeW5jIG9wZW4oKSB7XG4gICAgY29uc29sZS5pbmZvKFwiY29ubmVjdGVkIHRvIHNlcnZlclwiKTtcbiAgICAvLyBBdXRoZW50aWNhdGUgaWYgbmVlZGVkXG4gICAgaWYgKHRoaXMub3B0aW9ucy5wYXNzd29yZCkge1xuICAgICAgdHJ5IHtcbiAgICAgICAgYXdhaXQgdGhpcy5hdXRoV2l0aFBhc3N3b3JkKHRoaXMub3B0aW9ucy5wYXNzd29yZCk7XG4gICAgICB9IGNhdGNoIChlKSB7XG4gICAgICAgIHRoaXMuZmlyZShcImVycm9yXCIsIGUpO1xuICAgICAgICB0aGlzLmNsb3NlKCk7XG4gICAgICB9XG4gICAgfSBlbHNlIGlmICh0aGlzLm9wdGlvbnMuaW50ZXJhY3RpdmUpIHtcbiAgICAgIHRyeSB7XG4gICAgICAgIGF3YWl0IHRoaXMuYXV0aEludGVyYWN0aXZlKHRoaXMub3B0aW9ucy5pbnRlcmFjdGl2ZURhdGEgPz8ge30pO1xuICAgICAgfSBjYXRjaCAoZSkge1xuICAgICAgICB0aGlzLmZpcmUoXCJlcnJvclwiLCBlKTtcbiAgICAgICAgdGhpcy5jbG9zZSgpO1xuICAgICAgfVxuICAgIH1cbiAgICB0aGlzLnJlc3Vic2NyaWJlKCk7XG4gICAgdGhpcy5maXJlKFwib3BlblwiKTtcbiAgICB0aGlzLmZpcmUoXCJzdGF0ZUNoYW5nZVwiLCB0aGlzLnNvY2tldC5yZWFkeVN0YXRlKTtcbiAgfVxuXG4gIHByaXZhdGUgY2xvc2VkKGV2OiBDbG9zZUV2ZW50KSB7XG4gICAgY29uc29sZS53YXJuKGBsb3N0IGNvbm5lY3Rpb24gdG8gc2VydmVyOiAke2V2LnJlYXNvbn1gKTtcbiAgICB0aGlzLmZpcmUoXCJjbG9zZVwiLCBldik7XG4gICAgdGhpcy5maXJlKFwic3RhdGVDaGFuZ2VcIiwgdGhpcy5zb2NrZXQucmVhZHlTdGF0ZSk7XG4gICAgLy8gVHJ5IHJlY29ubmVjdGluZyBhZnRlciBhIGZldyBzZWNvbmRzXG4gICAgaWYgKHRoaXMub3B0aW9ucy5yZWNvbm5lY3QpIHtcbiAgICAgIHNldFRpbWVvdXQoKCkgPT4gdGhpcy5yZWNvbm5lY3QoKSwgNTAwMCk7XG4gICAgfVxuICB9XG5cbiAgcHJpdmF0ZSBlcnJvcmVkKGV2OiBFdmVudCkge1xuICAgIHRoaXMuZmlyZShcImVycm9yXCIsIGV2KTtcbiAgfVxuXG4gIHByaXZhdGUgcmVjZWl2ZWQoZXZlbnQ6IE1lc3NhZ2VFdmVudCkge1xuICAgIGNvbnN0IGV2ZW50cyA9IChldmVudC5kYXRhIGFzIHN0cmluZylcbiAgICAgIC5zcGxpdChcIlxcblwiKVxuICAgICAgLm1hcCgoZXYpID0+IGV2LnRyaW0oKSlcbiAgICAgIC5maWx0ZXIoKGV2KSA9PiBldi5sZW5ndGggPiAwKTtcbiAgICBldmVudHMuZm9yRWFjaCgoZXYpID0+IHtcbiAgICAgIGNvbnN0IHJlc3BvbnNlOiBLaWxvdm9sdE1lc3NhZ2UgPSBKU09OLnBhcnNlKGV2ID8/ICdcIlwiJyk7XG4gICAgICBpZiAoXCJlcnJvclwiIGluIHJlc3BvbnNlKSB7XG4gICAgICAgIHRoaXMuZmlyZShcImVycm9yXCIsIHJlc3BvbnNlKTtcbiAgICAgICAgaWYgKFwicmVxdWVzdF9pZFwiIGluIHJlc3BvbnNlICYmIHJlc3BvbnNlLnJlcXVlc3RfaWQgaW4gdGhpcy5wZW5kaW5nKSB7XG4gICAgICAgICAgdGhpcy5wZW5kaW5nW3Jlc3BvbnNlLnJlcXVlc3RfaWRdKHJlc3BvbnNlKTtcbiAgICAgICAgICBkZWxldGUgdGhpcy5wZW5kaW5nW3Jlc3BvbnNlLnJlcXVlc3RfaWRdO1xuICAgICAgICB9XG4gICAgICAgIHJldHVybjtcbiAgICAgIH1cbiAgICAgIHN3aXRjaCAocmVzcG9uc2UudHlwZSkge1xuICAgICAgICBjYXNlIFwicmVzcG9uc2VcIjpcbiAgICAgICAgICBpZiAocmVzcG9uc2UucmVxdWVzdF9pZCBpbiB0aGlzLnBlbmRpbmcpIHtcbiAgICAgICAgICAgIHRoaXMucGVuZGluZ1tyZXNwb25zZS5yZXF1ZXN0X2lkXShyZXNwb25zZSk7XG4gICAgICAgICAgICBkZWxldGUgdGhpcy5wZW5kaW5nW3Jlc3BvbnNlLnJlcXVlc3RfaWRdO1xuICAgICAgICAgIH0gZWxzZSB7XG4gICAgICAgICAgICBjb25zb2xlLndhcm4oXG4gICAgICAgICAgICAgIFwiUmVjZWl2ZWQgYSByZXNwb25zZSBmb3IgYW4gdW5yZWdpc3RlcmVkIHJlcXVlc3Q6IFwiLFxuICAgICAgICAgICAgICByZXNwb25zZVxuICAgICAgICAgICAgKTtcbiAgICAgICAgICB9XG4gICAgICAgICAgYnJlYWs7XG4gICAgICAgIGNhc2UgXCJwdXNoXCI6IHtcbiAgICAgICAgICBpZiAocmVzcG9uc2Uua2V5IGluIHRoaXMua2V5U3Vic2NyaXB0aW9ucykge1xuICAgICAgICAgICAgdGhpcy5rZXlTdWJzY3JpcHRpb25zW3Jlc3BvbnNlLmtleV0uZm9yRWFjaCgoZm4pID0+XG4gICAgICAgICAgICAgIGZuKHJlc3BvbnNlLm5ld192YWx1ZSwgcmVzcG9uc2Uua2V5KVxuICAgICAgICAgICAgKTtcbiAgICAgICAgICB9XG4gICAgICAgICAgT2JqZWN0LmVudHJpZXModGhpcy5wcmVmaXhTdWJzY3JpcHRpb25zKVxuICAgICAgICAgICAgLmZpbHRlcigoW2tdKSA9PiByZXNwb25zZS5rZXkuc3RhcnRzV2l0aChrKSlcbiAgICAgICAgICAgIC5mb3JFYWNoKChbXywgc3Vic2NyaWJlcnNdKSA9PiB7XG4gICAgICAgICAgICAgIHN1YnNjcmliZXJzLmZvckVhY2goKGZuKSA9PiBmbihyZXNwb25zZS5uZXdfdmFsdWUsIHJlc3BvbnNlLmtleSkpO1xuICAgICAgICAgICAgfSk7XG4gICAgICAgICAgYnJlYWs7XG4gICAgICAgIH1cbiAgICAgICAgZGVmYXVsdDpcbiAgICAgICAgLy8gRG8gbm90aGluZ1xuICAgICAgfVxuICAgIH0pO1xuICB9XG5cbiAgcHJpdmF0ZSBhc3luYyBhdXRoV2l0aFBhc3N3b3JkKHBhc3N3b3JkOiBzdHJpbmcpIHtcbiAgICAvLyBBc2sgZm9yIGNoYWxsZW5nZVxuICAgIGNvbnN0IHJlcXVlc3QgPSAoYXdhaXQgdGhpcy5zZW5kPGt2TG9naW4+KHtcbiAgICAgIGNvbW1hbmQ6IFwia2xvZ2luXCIsXG4gICAgICBkYXRhOiB7IGF1dGg6IFwiY2hhbGxlbmdlXCIgfSxcbiAgICB9KSkgYXMga3ZFcnJvciB8IGt2R2VuZXJpY1Jlc3BvbnNlPHsgY2hhbGxlbmdlOiBzdHJpbmc7IHNhbHQ6IHN0cmluZyB9PjtcbiAgICBpZiAoXCJlcnJvclwiIGluIHJlcXVlc3QpIHtcbiAgICAgIGNvbnNvbGUuZXJyb3IoXCJraWxvdm9sdCBhdXRoIGVycm9yOlwiLCByZXF1ZXN0LmVycm9yKTtcbiAgICAgIHRocm93IG5ldyBFcnJvcihyZXF1ZXN0LmVycm9yKTtcbiAgICB9XG4gICAgLy8gQ2FsY3VsYXRlIGhhc2ggYW5kIHNlbmQgYmFja1xuICAgIGNvbnN0IGhhc2ggPSBhd2FpdCBhdXRoQ2hhbGxlbmdlKFxuICAgICAgcGFzc3dvcmQgPz8gXCJcIixcbiAgICAgIHJlcXVlc3QuZGF0YS5jaGFsbGVuZ2UsXG4gICAgICByZXF1ZXN0LmRhdGEuc2FsdFxuICAgICk7XG4gICAgY29uc3QgcmVzcG9uc2UgPSAoYXdhaXQgdGhpcy5zZW5kPGt2QXV0aD4oe1xuICAgICAgY29tbWFuZDogXCJrYXV0aFwiLFxuICAgICAgZGF0YTogeyBoYXNoIH0sXG4gICAgfSkpIGFzIGt2RXJyb3IgfCBrdkVtcHR5UmVzcG9uc2U7XG4gICAgaWYgKFwiZXJyb3JcIiBpbiByZXNwb25zZSkge1xuICAgICAgY29uc29sZS5lcnJvcihcImtpbG92b2x0IGF1dGggZXJyb3I6XCIsIHJlc3BvbnNlLmVycm9yKTtcbiAgICAgIHRocm93IG5ldyBFcnJvcihyZXNwb25zZS5lcnJvcik7XG4gICAgfVxuICB9XG5cbiAgcHJpdmF0ZSBhc3luYyBhdXRoSW50ZXJhY3RpdmUoZGF0YTogUmVjb3JkPHN0cmluZywgdW5rbm93bj4pIHtcbiAgICAvLyBBc2sgZm9yIGludGVyYWN0aXZlIGF1dGhcbiAgICBjb25zdCByZXF1ZXN0ID0gKGF3YWl0IHRoaXMuc2VuZDxrdkxvZ2luPih7XG4gICAgICBjb21tYW5kOiBcImtsb2dpblwiLFxuICAgICAgZGF0YTogeyAuLi5kYXRhLCBhdXRoOiBcImFza1wiIH0sXG4gICAgfSkpIGFzIGt2RXJyb3IgfCBrdkdlbmVyaWNSZXNwb25zZTx7IGNoYWxsZW5nZTogc3RyaW5nOyBzYWx0OiBzdHJpbmcgfT47XG4gICAgaWYgKFwiZXJyb3JcIiBpbiByZXF1ZXN0KSB7XG4gICAgICBjb25zb2xlLmVycm9yKFwia2lsb3ZvbHQgYXV0aCBlcnJvcjpcIiwgcmVxdWVzdC5lcnJvcik7XG4gICAgICB0aHJvdyBuZXcgRXJyb3IocmVxdWVzdC5lcnJvcik7XG4gICAgfVxuICB9XG5cbiAgcHJpdmF0ZSBhc3luYyByZXN1YnNjcmliZSgpIHtcbiAgICBmb3IgKGNvbnN0IGtleSBpbiB0aGlzLmtleVN1YnNjcmlwdGlvbnMpIHtcbiAgICAgIGF3YWl0IHRoaXMuc2VuZDxrdlN1YnNjcmliZUtleT4oe1xuICAgICAgICBjb21tYW5kOiBcImtzdWJcIixcbiAgICAgICAgZGF0YToge1xuICAgICAgICAgIGtleSxcbiAgICAgICAgfSxcbiAgICAgIH0pO1xuICAgIH1cbiAgICBmb3IgKGNvbnN0IHByZWZpeCBpbiB0aGlzLnByZWZpeFN1YnNjcmlwdGlvbnMpIHtcbiAgICAgIHRoaXMuc2VuZDxrdlN1YnNjcmliZVByZWZpeD4oe1xuICAgICAgICBjb21tYW5kOiBcImtzdWItcHJlZml4XCIsXG4gICAgICAgIGRhdGE6IHtcbiAgICAgICAgICBwcmVmaXgsXG4gICAgICAgIH0sXG4gICAgICB9KTtcbiAgICB9XG4gIH1cblxuICAvKipcbiAgICogU2VuZCBhIHJlcXVlc3QgdG8gdGhlIHNlcnZlclxuICAgKiBAcGFyYW0gbXNnIFJlcXVlc3QgdG8gc2VuZFxuICAgKiBAcmV0dXJucyBSZXNwb25zZSBmcm9tIHNlcnZlclxuICAgKi9cbiAgc2VuZDxUIGV4dGVuZHMgS2lsb3ZvbHRSZXF1ZXN0PihcbiAgICBtc2c6IFQgfCBPbWl0PFQsIFwicmVxdWVzdF9pZFwiPlxuICApOiBQcm9taXNlPEtpbG92b2x0TWVzc2FnZT4ge1xuICAgIGlmICh0aGlzLnNvY2tldC5yZWFkeVN0YXRlICE9PSB0aGlzLnNvY2tldC5PUEVOKSB7XG4gICAgICB0aHJvdyBuZXcgRXJyb3IoXCJOb3QgY29ubmVjdGVkIHRvIHNlcnZlclwiKTtcbiAgICB9XG4gICAgY29uc3QgbWVzc2FnZSA9IHtcbiAgICAgIC4uLm1zZyxcbiAgICAgIHJlcXVlc3RfaWQ6IFwicmVxdWVzdF9pZFwiIGluIG1zZyA/IG1zZy5yZXF1ZXN0X2lkIDogZ2VuZXJhdGVSaWQoKSxcbiAgICB9O1xuICAgIHJldHVybiBuZXcgUHJvbWlzZSgocmVzb2x2ZSkgPT4ge1xuICAgICAgY29uc3QgcGF5bG9hZCA9IEpTT04uc3RyaW5naWZ5KG1lc3NhZ2UpO1xuICAgICAgdGhpcy5zb2NrZXQuc2VuZChwYXlsb2FkKTtcbiAgICAgIHRoaXMucGVuZGluZ1ttZXNzYWdlLnJlcXVlc3RfaWRdID0gcmVzb2x2ZTtcbiAgICB9KTtcbiAgfVxuXG4gIC8qKlxuICAgKiBTZXQgYSBrZXkgdG8gYSBzcGVjaWZpZWQgdmFsdWVcbiAgICogQHBhcmFtIGtleSBLZXkgdG8gc2V0XG4gICAqIEBwYXJhbSBkYXRhIFZhbHVlIHRvIHNldFxuICAgKiBAcmV0dXJucyBSZXBseSBmcm9tIHNlcnZlclxuICAgKi9cbiAgcHV0S2V5KGtleTogc3RyaW5nLCBkYXRhOiBzdHJpbmcpOiBQcm9taXNlPEtpbG92b2x0TWVzc2FnZT4ge1xuICAgIHJldHVybiB0aGlzLnNlbmQ8a3ZTZXQ+KHtcbiAgICAgIGNvbW1hbmQ6IFwia3NldFwiLFxuICAgICAgZGF0YToge1xuICAgICAgICBrZXksXG4gICAgICAgIGRhdGEsXG4gICAgICB9LFxuICAgIH0pO1xuICB9XG5cbiAgLyoqXG4gICAqIFNldCBtdWx0aXBsZSBrZXlzIGF0IG9uY2VcbiAgICogQHBhcmFtIGRhdGEgTWFwIG9mIGtleTp2YWx1ZSBkYXRhIHRvIHNldFxuICAgKiBAcmV0dXJucyBSZXBseSBmcm9tIHNlcnZlclxuICAgKi9cbiAgcHV0S2V5cyhkYXRhOiBSZWNvcmQ8c3RyaW5nLCBzdHJpbmc+KTogUHJvbWlzZTxLaWxvdm9sdE1lc3NhZ2U+IHtcbiAgICByZXR1cm4gdGhpcy5zZW5kPGt2U2V0QnVsaz4oe1xuICAgICAgY29tbWFuZDogXCJrc2V0LWJ1bGtcIixcbiAgICAgIGRhdGEsXG4gICAgfSk7XG4gIH1cblxuICAvKipcbiAgICogU2V0IGEga2V5IHRvIHRoZSBKU09OIHJlcHJlc2VudGF0aW9uIG9mIGFuIG9iamVjdFxuICAgKiBAcGFyYW0ga2V5IEtleSB0byBzZXRcbiAgICogQHBhcmFtIGRhdGEgT2JqZWN0IHRvIHNhdmVcbiAgICogQHJldHVybnMgUmVwbHkgZnJvbSBzZXJ2ZXJcbiAgICovXG4gIHB1dEpTT048VD4oa2V5OiBzdHJpbmcsIGRhdGE6IFQpOiBQcm9taXNlPEtpbG92b2x0TWVzc2FnZT4ge1xuICAgIHJldHVybiB0aGlzLnNlbmQ8a3ZTZXQ+KHtcbiAgICAgIGNvbW1hbmQ6IFwia3NldFwiLFxuICAgICAgZGF0YToge1xuICAgICAgICBrZXksXG4gICAgICAgIGRhdGE6IEpTT04uc3RyaW5naWZ5KGRhdGEpLFxuICAgICAgfSxcbiAgICB9KTtcbiAgfVxuXG4gIC8qKlxuICAgKiBTZXQgbXVsdGlwbGUga2V5cyBhdCBvbmNlXG4gICAqIEBwYXJhbSBkYXRhIE1hcCBvZiBrZXk6dmFsdWUgZGF0YSB0byBzZXRcbiAgICogQHJldHVybnMgUmVwbHkgZnJvbSBzZXJ2ZXJcbiAgICovXG4gIHB1dEpTT05zKGRhdGE6IFJlY29yZDxzdHJpbmcsIHVua25vd24+KTogUHJvbWlzZTxLaWxvdm9sdE1lc3NhZ2U+IHtcbiAgICBjb25zdCBqc29uRGF0YTogUmVjb3JkPHN0cmluZywgc3RyaW5nPiA9IHt9O1xuICAgIE9iamVjdC5lbnRyaWVzKGRhdGEpLmZvckVhY2goKFtrLCB2XSkgPT4ge1xuICAgICAganNvbkRhdGFba10gPSBKU09OLnN0cmluZ2lmeSh2KTtcbiAgICB9KTtcbiAgICByZXR1cm4gdGhpcy5zZW5kPGt2U2V0QnVsaz4oe1xuICAgICAgY29tbWFuZDogXCJrc2V0LWJ1bGtcIixcbiAgICAgIGRhdGE6IGpzb25EYXRhLFxuICAgIH0pO1xuICB9XG5cbiAgLyoqXG4gICAqIFJldHJpZXZlIHZhbHVlIGZvciBrZXlcbiAgICogQHBhcmFtIGtleSBLZXkgdG8gcmV0cmlldmVcbiAgICogQHJldHVybnMgUmVwbHkgZnJvbSBzZXJ2ZXJcbiAgICovXG4gIGFzeW5jIGdldEtleShrZXk6IHN0cmluZyk6IFByb21pc2U8c3RyaW5nPiB7XG4gICAgY29uc3QgcmVzcG9uc2UgPSAoYXdhaXQgdGhpcy5zZW5kPGt2R2V0Pih7XG4gICAgICBjb21tYW5kOiBcImtnZXRcIixcbiAgICAgIGRhdGE6IHtcbiAgICAgICAga2V5LFxuICAgICAgfSxcbiAgICB9KSkgYXMga3ZFcnJvciB8IGt2R2VuZXJpY1Jlc3BvbnNlPHN0cmluZz47XG4gICAgaWYgKFwiZXJyb3JcIiBpbiByZXNwb25zZSkge1xuICAgICAgdGhyb3cgbmV3IEVycm9yKHJlc3BvbnNlLmVycm9yKTtcbiAgICB9XG4gICAgcmV0dXJuIHJlc3BvbnNlLmRhdGE7XG4gIH1cblxuICAvKipcbiAgICogUmV0cmlldmUgdmFsdWUgZm9yIGtleVxuICAgKiBAcGFyYW0ga2V5cyBLZXlzIHRvIHJldHJpZXZlXG4gICAqIEByZXR1cm5zIFJlcGx5IGZyb20gc2VydmVyXG4gICAqL1xuICBhc3luYyBnZXRLZXlzKGtleXM6IHN0cmluZ1tdKTogUHJvbWlzZTxSZWNvcmQ8c3RyaW5nLCBzdHJpbmc+PiB7XG4gICAgY29uc3QgcmVzcG9uc2UgPSAoYXdhaXQgdGhpcy5zZW5kPGt2R2V0QnVsaz4oe1xuICAgICAgY29tbWFuZDogXCJrZ2V0LWJ1bGtcIixcbiAgICAgIGRhdGE6IHtcbiAgICAgICAga2V5cyxcbiAgICAgIH0sXG4gICAgfSkpIGFzIGt2RXJyb3IgfCBrdkdlbmVyaWNSZXNwb25zZTxSZWNvcmQ8c3RyaW5nLCBzdHJpbmc+PjtcbiAgICBpZiAoXCJlcnJvclwiIGluIHJlc3BvbnNlKSB7XG4gICAgICB0aHJvdyBuZXcgRXJyb3IocmVzcG9uc2UuZXJyb3IpO1xuICAgIH1cbiAgICByZXR1cm4gcmVzcG9uc2UuZGF0YTtcbiAgfVxuXG4gIC8qKlxuICAgKiBSZXRyaWV2ZSBhbGwga2V5cyB3aXRoIGdpdmVuIHByZWZpeFxuICAgKiBAcGFyYW0gcHJlZml4IFByZWZpeCBmb3Iga2V5cyB0byByZXRyaWV2ZVxuICAgKiBAcmV0dXJucyBSZXBseSBmcm9tIHNlcnZlclxuICAgKi9cbiAgYXN5bmMgZ2V0S2V5c0J5UHJlZml4KHByZWZpeDogc3RyaW5nKTogUHJvbWlzZTxSZWNvcmQ8c3RyaW5nLCBzdHJpbmc+PiB7XG4gICAgY29uc3QgcmVzcG9uc2UgPSAoYXdhaXQgdGhpcy5zZW5kPGt2R2V0QWxsPih7XG4gICAgICBjb21tYW5kOiBcImtnZXQtYWxsXCIsXG4gICAgICBkYXRhOiB7XG4gICAgICAgIHByZWZpeCxcbiAgICAgIH0sXG4gICAgfSkpIGFzIGt2RXJyb3IgfCBrdkdlbmVyaWNSZXNwb25zZTxSZWNvcmQ8c3RyaW5nLCBzdHJpbmc+PjtcbiAgICBpZiAoXCJlcnJvclwiIGluIHJlc3BvbnNlKSB7XG4gICAgICB0aHJvdyBuZXcgRXJyb3IocmVzcG9uc2UuZXJyb3IpO1xuICAgIH1cbiAgICByZXR1cm4gcmVzcG9uc2UuZGF0YTtcbiAgfVxuXG4gIC8qKlxuICAgKiBSZXRyaWV2ZSBvYmplY3QgZnJvbSBrZXksIGRlc2VyaWFsaXplZCBmcm9tIEpTT04uXG4gICAqIEl0J3MgeW91ciByZXNwb25zaWJpbGl0eSB0byBtYWtlIHN1cmUgdGhlIG9iamVjdCBpcyBhY3R1YWxseSB3aGF0IHlvdSBleHBlY3RcbiAgICogQHBhcmFtIGtleSBLZXkgdG8gcmV0cmlldmVcbiAgICogQHJldHVybnMgUmVwbHkgZnJvbSBzZXJ2ZXJcbiAgICovXG4gIGFzeW5jIGdldEpTT048VD4oa2V5OiBzdHJpbmcpOiBQcm9taXNlPFQ+IHtcbiAgICBjb25zdCByZXNwb25zZSA9IChhd2FpdCB0aGlzLnNlbmQ8a3ZHZXQ+KHtcbiAgICAgIGNvbW1hbmQ6IFwia2dldFwiLFxuICAgICAgZGF0YToge1xuICAgICAgICBrZXksXG4gICAgICB9LFxuICAgIH0pKSBhcyBrdkVycm9yIHwga3ZHZW5lcmljUmVzcG9uc2U8c3RyaW5nPjtcbiAgICBpZiAoXCJlcnJvclwiIGluIHJlc3BvbnNlKSB7XG4gICAgICB0aHJvdyBuZXcgRXJyb3IocmVzcG9uc2UuZXJyb3IpO1xuICAgIH1cbiAgICByZXR1cm4gSlNPTi5wYXJzZShyZXNwb25zZS5kYXRhKTtcbiAgfVxuXG4gIC8qKlxuICAgKiBSZXRyaWV2ZSBvYmplY3RzIGZyb20ga2V5cywgZGVzZXJpYWxpemVkIGZyb20gSlNPTi5cbiAgICogSXQncyB5b3VyIHJlc3BvbnNpYmlsaXR5IHRvIG1ha2Ugc3VyZSB0aGUgb2JqZWN0IGlzIGFjdHVhbGx5IHdoYXQgeW91IGV4cGVjdFxuICAgKiBAcGFyYW0ga2V5IEtleSB0byByZXRyaWV2ZVxuICAgKiBAcmV0dXJucyBSZXBseSBmcm9tIHNlcnZlclxuICAgKi9cbiAgYXN5bmMgZ2V0SlNPTnM8VD4oa2V5czogc3RyaW5nW10pOiBQcm9taXNlPFQ+IHtcbiAgICBjb25zdCByZXNwb25zZSA9IChhd2FpdCB0aGlzLnNlbmQ8a3ZHZXRCdWxrPih7XG4gICAgICBjb21tYW5kOiBcImtnZXQtYnVsa1wiLFxuICAgICAgZGF0YToge1xuICAgICAgICBrZXlzLFxuICAgICAgfSxcbiAgICB9KSkgYXMga3ZFcnJvciB8IGt2R2VuZXJpY1Jlc3BvbnNlPFJlY29yZDxzdHJpbmcsIHN0cmluZz4+O1xuICAgIGlmIChcImVycm9yXCIgaW4gcmVzcG9uc2UpIHtcbiAgICAgIHRocm93IG5ldyBFcnJvcihyZXNwb25zZS5lcnJvcik7XG4gICAgfVxuICAgIGNvbnN0IHJldHVybkRhdGE6IFJlY29yZDxzdHJpbmcsIHVua25vd24+ID0ge307XG4gICAgT2JqZWN0LmVudHJpZXMocmVzcG9uc2UuZGF0YSkuZm9yRWFjaCgoW2ssIHZdKSA9PiB7XG4gICAgICByZXR1cm5EYXRhW2tdID0gSlNPTi5wYXJzZSh2KTtcbiAgICB9KTtcbiAgICByZXR1cm4gcmV0dXJuRGF0YSBhcyBUO1xuICB9XG5cbiAgLyoqXG4gICAqIFN1YnNjcmliZSB0byBrZXkgY2hhbmdlc1xuICAgKiBAcGFyYW0ga2V5IEtleSB0byBzdWJzY3JpYmUgdG9cbiAgICogQHBhcmFtIGZuIENhbGxiYWNrIHRvIGNhbGwgd2hlbiBrZXkgY2hhbmdlc1xuICAgKiBAcmV0dXJucyBSZXBseSBmcm9tIHNlcnZlclxuICAgKi9cbiAgc3Vic2NyaWJlS2V5KGtleTogc3RyaW5nLCBmbjogU3Vic2NyaXB0aW9uSGFuZGxlcik6IFByb21pc2U8S2lsb3ZvbHRNZXNzYWdlPiB7XG4gICAgaWYgKGtleSBpbiB0aGlzLmtleVN1YnNjcmlwdGlvbnMpIHtcbiAgICAgIHRoaXMua2V5U3Vic2NyaXB0aW9uc1trZXldLnB1c2goZm4pO1xuICAgIH0gZWxzZSB7XG4gICAgICB0aGlzLmtleVN1YnNjcmlwdGlvbnNba2V5XSA9IFtmbl07XG4gICAgfVxuXG4gICAgcmV0dXJuIHRoaXMuc2VuZDxrdlN1YnNjcmliZUtleT4oe1xuICAgICAgY29tbWFuZDogXCJrc3ViXCIsXG4gICAgICBkYXRhOiB7XG4gICAgICAgIGtleSxcbiAgICAgIH0sXG4gICAgfSk7XG4gIH1cblxuICAvKipcbiAgICogU3RvcCBjYWxsaW5nIGEgY2FsbGJhY2sgd2hlbiBpdHMgcmVsYXRlZCBrZXkgY2hhbmdlc1xuICAgKiBUaGlzIG9ubHlcbiAgICogQHBhcmFtIGtleSBLZXkgdG8gdW5zdWJzY3JpYmUgZnJvbVxuICAgKiBAcGFyYW0gZm4gQ2FsbGJhY2sgdG8gc3RvcCBjYWxsaW5nXG4gICAqIEByZXR1cm5zIHRydWUgaWYgYSBzdWJzY3JpcHRpb24gd2FzIHJlbW92ZWQsIGZhbHNlIG90aGVyd2lzZVxuICAgKi9cbiAgYXN5bmMgdW5zdWJzY3JpYmVLZXkoa2V5OiBzdHJpbmcsIGZuOiBTdWJzY3JpcHRpb25IYW5kbGVyKTogUHJvbWlzZTxib29sZWFuPiB7XG4gICAgaWYgKCEoa2V5IGluIHRoaXMua2V5U3Vic2NyaXB0aW9ucykpIHtcbiAgICAgIC8vIE5vIHN1YnNjcmlwdGlvbnMsIGp1c3Qgd2FybiBhbmQgcmV0dXJuXG4gICAgICBjb25zb2xlLndhcm4oXG4gICAgICAgIGBUcnlpbmcgdG8gdW5zdWJzY3JpYmUgZnJvbSBrZXkgXCIke2tleX1cIiBidXQgbm8gc3Vic2NyaXB0aW9ucyBjb3VsZCBiZSBmb3VuZCFgXG4gICAgICApO1xuICAgICAgcmV0dXJuIGZhbHNlO1xuICAgIH1cblxuICAgIC8vIEdldCBzdWJzY3JpYmVyIGluIGxpc3RcbiAgICBjb25zdCBpbmRleCA9IHRoaXMua2V5U3Vic2NyaXB0aW9uc1trZXldLmZpbmRJbmRleCgoc3ViZm4pID0+IHN1YmZuID09PSBmbik7XG4gICAgaWYgKGluZGV4IDwgMCkge1xuICAgICAgLy8gTm8gc3Vic2NyaXB0aW9ucywganVzdCB3YXJuIGFuZCByZXR1cm5cbiAgICAgIGNvbnNvbGUud2FybihcbiAgICAgICAgYFRyeWluZyB0byB1bnN1YnNjcmliZSBmcm9tIGtleSBcIiR7a2V5fVwiIGJ1dCBzcGVjaWZpZWQgZnVuY3Rpb24gaXMgbm90IGluIHRoZSBzdWJzY3JpYmVycyFgXG4gICAgICApO1xuICAgICAgcmV0dXJuIGZhbHNlO1xuICAgIH1cblxuICAgIC8vIFJlbW92ZSBzdWJzY3JpYmVyIGZyb20gbGlzdFxuICAgIHRoaXMua2V5U3Vic2NyaXB0aW9uc1trZXldLnNwbGljZShpbmRleCwgMSk7XG5cbiAgICAvLyBDaGVjayBpZiBhcnJheSBpcyBlbXB0eVxuICAgIGlmICh0aGlzLmtleVN1YnNjcmlwdGlvbnNba2V5XS5sZW5ndGggPCAxKSB7XG4gICAgICAvLyBTZW5kIHVuc3Vic2NyaWJlXG4gICAgICBjb25zdCByZXMgPSAoYXdhaXQgdGhpcy5zZW5kPGt2VW5zdWJzY3JpYmVLZXk+KHtcbiAgICAgICAgY29tbWFuZDogXCJrdW5zdWJcIixcbiAgICAgICAgZGF0YToge1xuICAgICAgICAgIGtleSxcbiAgICAgICAgfSxcbiAgICAgIH0pKSBhcyBrdkVycm9yIHwga3ZHZW5lcmljUmVzcG9uc2U8dm9pZD47XG4gICAgICBpZiAoXCJlcnJvclwiIGluIHJlcykge1xuICAgICAgICBjb25zb2xlLndhcm4oYHVuc3Vic2NyaWJlIGZhaWxlZDogJHtyZXMuZXJyb3J9YCk7XG4gICAgICB9XG4gICAgICByZXR1cm4gcmVzLm9rO1xuICAgIH1cblxuICAgIHJldHVybiB0cnVlO1xuICB9XG5cbiAgLyoqXG4gICAqIFN1YnNjcmliZSB0byBrZXkgY2hhbmdlcyBvbiBhIHByZWZpeFxuICAgKiBAcGFyYW0gcHJlZml4IFByZWZpeCBvZiBrZXlzIHRvIHN1YnNjcmliZSB0b1xuICAgKiBAcGFyYW0gZm4gQ2FsbGJhY2sgdG8gY2FsbCB3aGVuIGtleSBjaGFuZ2VzXG4gICAqIEByZXR1cm5zIFJlcGx5IGZyb20gc2VydmVyXG4gICAqL1xuICBzdWJzY3JpYmVQcmVmaXgoXG4gICAgcHJlZml4OiBzdHJpbmcsXG4gICAgZm46IFN1YnNjcmlwdGlvbkhhbmRsZXJcbiAgKTogUHJvbWlzZTxLaWxvdm9sdE1lc3NhZ2U+IHtcbiAgICBpZiAocHJlZml4IGluIHRoaXMua2V5U3Vic2NyaXB0aW9ucykge1xuICAgICAgdGhpcy5wcmVmaXhTdWJzY3JpcHRpb25zW3ByZWZpeF0ucHVzaChmbik7XG4gICAgfSBlbHNlIHtcbiAgICAgIHRoaXMucHJlZml4U3Vic2NyaXB0aW9uc1twcmVmaXhdID0gW2ZuXTtcbiAgICB9XG5cbiAgICByZXR1cm4gdGhpcy5zZW5kPGt2U3Vic2NyaWJlUHJlZml4Pih7XG4gICAgICBjb21tYW5kOiBcImtzdWItcHJlZml4XCIsXG4gICAgICBkYXRhOiB7XG4gICAgICAgIHByZWZpeCxcbiAgICAgIH0sXG4gICAgfSk7XG4gIH1cblxuICAvKipcbiAgICogU3RvcCBjYWxsaW5nIGEgY2FsbGJhY2sgd2hlbiB0aGVpciBwcmVmaXgncyByZWxhdGVkIGtleSBjaGFuZ2VzXG4gICAqIFRoaXMgb25seVxuICAgKiBAcGFyYW0gcHJlZml4IFByZWZpeCB0byB1bnN1YnNjcmliZSBmcm9tXG4gICAqIEBwYXJhbSBmbiBDYWxsYmFjayB0byBzdG9wIGNhbGxpbmdcbiAgICogQHJldHVybnMgdHJ1ZSBpZiBhIHN1YnNjcmlwdGlvbiB3YXMgcmVtb3ZlZCwgZmFsc2Ugb3RoZXJ3aXNlXG4gICAqL1xuICBhc3luYyB1bnN1YnNjcmliZVByZWZpeChcbiAgICBwcmVmaXg6IHN0cmluZyxcbiAgICBmbjogU3Vic2NyaXB0aW9uSGFuZGxlclxuICApOiBQcm9taXNlPGJvb2xlYW4+IHtcbiAgICBpZiAoIShwcmVmaXggaW4gdGhpcy5wcmVmaXhTdWJzY3JpcHRpb25zKSkge1xuICAgICAgLy8gTm8gc3Vic2NyaXB0aW9ucywganVzdCB3YXJuIGFuZCByZXR1cm5cbiAgICAgIGNvbnNvbGUud2FybihcbiAgICAgICAgYFRyeWluZyB0byB1bnN1YnNjcmliZSBmcm9tIHByZWZpeCBcIiR7cHJlZml4fVwiIGJ1dCBubyBzdWJzY3JpcHRpb25zIGNvdWxkIGJlIGZvdW5kIWBcbiAgICAgICk7XG4gICAgICByZXR1cm4gZmFsc2U7XG4gICAgfVxuXG4gICAgLy8gR2V0IHN1YnNjcmliZXIgaW4gbGlzdFxuICAgIGNvbnN0IGluZGV4ID0gdGhpcy5wcmVmaXhTdWJzY3JpcHRpb25zW3ByZWZpeF0uZmluZEluZGV4KFxuICAgICAgKHN1YmZuKSA9PiBzdWJmbiA9PT0gZm5cbiAgICApO1xuICAgIGlmIChpbmRleCA8IDApIHtcbiAgICAgIC8vIE5vIHN1YnNjcmlwdGlvbnMsIGp1c3Qgd2FybiBhbmQgcmV0dXJuXG4gICAgICBjb25zb2xlLndhcm4oXG4gICAgICAgIGBUcnlpbmcgdG8gdW5zdWJzY3JpYmUgZnJvbSBrZXkgXCIke3ByZWZpeH1cIiBidXQgc3BlY2lmaWVkIGZ1bmN0aW9uIGlzIG5vdCBpbiB0aGUgc3Vic2NyaWJlcnMhYFxuICAgICAgKTtcbiAgICAgIHJldHVybiBmYWxzZTtcbiAgICB9XG5cbiAgICAvLyBSZW1vdmUgc3Vic2NyaWJlciBmcm9tIGxpc3RcbiAgICB0aGlzLnByZWZpeFN1YnNjcmlwdGlvbnNbcHJlZml4XS5zcGxpY2UoaW5kZXgsIDEpO1xuXG4gICAgLy8gQ2hlY2sgaWYgYXJyYXkgaXMgZW1wdHlcbiAgICBpZiAodGhpcy5wcmVmaXhTdWJzY3JpcHRpb25zW3ByZWZpeF0ubGVuZ3RoIDwgMSkge1xuICAgICAgLy8gU2VuZCB1bnN1YnNjcmliZVxuICAgICAgY29uc3QgcmVzID0gKGF3YWl0IHRoaXMuc2VuZDxrdlVuc3Vic2NyaWJlUHJlZml4Pih7XG4gICAgICAgIGNvbW1hbmQ6IFwia3Vuc3ViLXByZWZpeFwiLFxuICAgICAgICBkYXRhOiB7XG4gICAgICAgICAgcHJlZml4LFxuICAgICAgICB9LFxuICAgICAgfSkpIGFzIGt2RXJyb3IgfCBrdkdlbmVyaWNSZXNwb25zZTx2b2lkPjtcbiAgICAgIGlmIChcImVycm9yXCIgaW4gcmVzKSB7XG4gICAgICAgIGNvbnNvbGUud2FybihgdW5zdWJzY3JpYmUgZmFpbGVkOiAke3Jlcy5lcnJvcn1gKTtcbiAgICAgIH1cbiAgICAgIHJldHVybiByZXMub2s7XG4gICAgfVxuXG4gICAgcmV0dXJuIHRydWU7XG4gIH1cblxuICAvKipcbiAgICogUmV0dXJucyBhIGxpc3Qgb2Ygc2F2ZWQga2V5cyB3aXRoIHRoZSBnaXZlbiBwcmVmaXguXG4gICAqIElmIG5vIHByZWZpeCBpcyBnaXZlbiB0aGVuIHJldHVybnMgYWxsIHRoZSBrZXlzLlxuICAgKiBAcGFyYW0gcHJlZml4IE9wdGlvbmFsIHByZWZpeFxuICAgKiBAcmV0dXJucyBMaXN0IG9mIGtleXNcbiAgICovXG4gIGFzeW5jIGtleUxpc3QocHJlZml4Pzogc3RyaW5nKTogUHJvbWlzZTxzdHJpbmdbXT4ge1xuICAgIGNvbnN0IHJlc3BvbnNlID0gKGF3YWl0IHRoaXMuc2VuZDxrdktleUxpc3Q+KHtcbiAgICAgIGNvbW1hbmQ6IFwia2xpc3RcIixcbiAgICAgIGRhdGE6IHtcbiAgICAgICAgcHJlZml4OiBwcmVmaXggPz8gXCJcIixcbiAgICAgIH0sXG4gICAgfSkpIGFzIGt2RXJyb3IgfCBrdkdlbmVyaWNSZXNwb25zZTxzdHJpbmdbXT47XG5cbiAgICBpZiAoXCJlcnJvclwiIGluIHJlc3BvbnNlKSB7XG4gICAgICB0aHJvdyBuZXcgRXJyb3IocmVzcG9uc2UuZXJyb3IpO1xuICAgIH1cblxuICAgIHJldHVybiByZXNwb25zZS5kYXRhO1xuICB9XG5cbiAgLyoqXG4gICAqIERlbGV0ZSBrZXkgZnJvbSBzdG9yZVxuICAgKiBAcGFyYW0ga2V5IEtleSB0byBkZWxldGVcbiAgICogQHJldHVybnMgUmVwbHkgZnJvbSBzZXJ2ZXJcbiAgICovXG4gIGFzeW5jIGRlbGV0ZUtleShrZXk6IHN0cmluZyk6IFByb21pc2U8c3RyaW5nPiB7XG4gICAgY29uc3QgcmVzcG9uc2UgPSAoYXdhaXQgdGhpcy5zZW5kPGt2RGVsZXRlPih7XG4gICAgICBjb21tYW5kOiBcImtkZWxcIixcbiAgICAgIGRhdGE6IHtcbiAgICAgICAga2V5LFxuICAgICAgfSxcbiAgICB9KSkgYXMga3ZFcnJvciB8IGt2R2VuZXJpY1Jlc3BvbnNlPHN0cmluZz47XG4gICAgaWYgKFwiZXJyb3JcIiBpbiByZXNwb25zZSkge1xuICAgICAgdGhyb3cgbmV3IEVycm9yKHJlc3BvbnNlLmVycm9yKTtcbiAgICB9XG4gICAgcmV0dXJuIHJlc3BvbnNlLmRhdGE7XG4gIH1cbn1cblxuZXhwb3J0IGRlZmF1bHQgS2lsb3ZvbHQ7XG4iLCJpbXBvcnQgeyBLaWxvdm9sdCB9IGZyb20gXCJodHRwczovL2Rlbm8ubGFuZC94L2tpbG92b2x0QHY4LjAuMC9tb2QudHNcIjtcclxuaW1wb3J0IHtcclxuICBDaGFubmVsVXBkYXRlRXZlbnQsXHJcbiAgQ2hlZXJFdmVudCxcclxuICBDdXN0b21SZXdhcmRSZWRlbXB0aW9uRXZlbnQsXHJcbiAgRXZlbnRTdWJVbmtub3duRXZlbnQsXHJcbiAgRm9sbG93RXZlbnQsXHJcbiAgUmFpZEV2ZW50LFxyXG4gIFJlc3Vic2NyaXB0aW9uRXZlbnQsXHJcbiAgU3Vic2NyaXB0aW9uRXZlbnQsXHJcbiAgU3Vic2NyaXB0aW9uR2lmdEV2ZW50LFxyXG4gIFR3aXRjaENoYXRNZXNzYWdlLFxyXG59IGZyb20gXCIuL3R5cGVzLnRzXCI7XHJcblxyXG5leHBvcnQgY2xhc3MgQ2hhdCB7XHJcbiAgY29uc3RydWN0b3IocHJpdmF0ZSByZWFkb25seSBrdjogS2lsb3ZvbHQpIHt9XHJcblxyXG4gIC8qKlxyXG4gICAqIExpc3RlbiBmb3IgbmV3IG1lc3NhZ2VzIGNvbWluZyBmcm9tIFR3aXRjaCBjaGF0XHJcbiAgICogQHBhcmFtIGNhbGxiYWNrIEZ1bmN0aW9uIHRvIGNhbGwgd2hlbiBhIG5ldyBtZXNzYWdlIGlzIHJlY2VpdmVkXHJcbiAgICovXHJcbiAgb25NZXNzYWdlKGNhbGxiYWNrOiAobWVzc2FnZTogVHdpdGNoQ2hhdE1lc3NhZ2UpID0+IHZvaWQpIHtcclxuICAgIHJldHVybiB0aGlzLmt2LnN1YnNjcmliZUtleShcclxuICAgICAgXCJ0d2l0Y2gvZXYvY2hhdC1tZXNzYWdlXCIsXHJcbiAgICAgIChuZXdWYWx1ZTogc3RyaW5nKSA9PiB7XHJcbiAgICAgICAgY29uc3QgbWVzc2FnZSA9IEpTT04ucGFyc2UobmV3VmFsdWUpIGFzIFR3aXRjaENoYXRNZXNzYWdlO1xyXG4gICAgICAgIGNhbGxiYWNrKG1lc3NhZ2UpO1xyXG4gICAgICB9XHJcbiAgICApO1xyXG4gIH1cclxuXHJcbiAgLyoqXHJcbiAgICogV3JpdGUgYSBwbGFpbiB0ZXh0IG1lc3NhZ2UgdG8gY2hhdCAoZW1vdGVzIHN1cHBvcnRlZClcclxuICAgKiBAcGFyYW0gbWVzc2FnZSBNZXNzYWdlIHRvIHdyaXRlXHJcbiAgICovXHJcbiAgd3JpdGVNZXNzYWdlKG1lc3NhZ2U6IHN0cmluZykge1xyXG4gICAgcmV0dXJuIHRoaXMua3YucHV0S2V5KFwidHdpdGNoL0BzZW5kLWNoYXQtbWVzc2FnZVwiLCBtZXNzYWdlKTtcclxuICB9XHJcbn1cclxuXHJcbmV4cG9ydCBjbGFzcyBFdmVudFN1YiB7XHJcbiAgY29uc3RydWN0b3IocHJpdmF0ZSByZWFkb25seSBrdjogS2lsb3ZvbHQpIHt9XHJcblxyXG4gIC8qKlxyXG4gICAqIEdlbmVyaWMgY2F0Y2gtYWxsIGxpc3RlbmVyIGZvciBhbGwgRXZlbnRTdWIgZXZlbnRzXHJcbiAgICogQHBhcmFtIGNhbGxiYWNrIEZ1bmN0aW9uIHRvIGNhbGwgd2hlbiBhIG5ldyBldmVudCBpcyByZWNlaXZlZFxyXG4gICAqL1xyXG4gIG9uRXZlbnRTdWJFdmVudChjYWxsYmFjazogKG1lc3NhZ2U6IEV2ZW50U3ViVW5rbm93bkV2ZW50KSA9PiB2b2lkKSB7XHJcbiAgICByZXR1cm4gdGhpcy5rdi5zdWJzY3JpYmVLZXkoXHJcbiAgICAgIFwidHdpdGNoL2V2L2V2ZW50c3ViLWV2ZW50XCIsXHJcbiAgICAgIChuZXdWYWx1ZTogc3RyaW5nKSA9PiB7XHJcbiAgICAgICAgY29uc3QgZXYgPSBKU09OLnBhcnNlKG5ld1ZhbHVlKSBhcyBFdmVudFN1YlVua25vd25FdmVudDtcclxuICAgICAgICBjYWxsYmFjayhldik7XHJcbiAgICAgIH1cclxuICAgICk7XHJcbiAgfVxyXG5cclxuICAvKipcclxuICAgKiBMaXN0ZW4gZm9yIG5ldyByZWRlZW1zXHJcbiAgICogQHBhcmFtIGNhbGxiYWNrIEZ1bmN0aW9uIHRvIGNhbGwgd2hlbiBzb21ldGhpbmcgaXMgcmVkZWVtZWRcclxuICAgKi9cclxuICBvblJlZGVlbShjYWxsYmFjazogKG1lc3NhZ2U6IEN1c3RvbVJld2FyZFJlZGVtcHRpb25FdmVudCkgPT4gdm9pZCkge1xyXG4gICAgcmV0dXJuIHRoaXMub25FdmVudFN1YkV2ZW50KChldjogRXZlbnRTdWJVbmtub3duRXZlbnQpID0+IHtcclxuICAgICAgaWYgKFxyXG4gICAgICAgIGV2LnN1YnNjcmlwdGlvbi50eXBlICE9PVxyXG4gICAgICAgIFwiY2hhbm5lbC5jaGFubmVsX3BvaW50c19jdXN0b21fcmV3YXJkX3JlZGVtcHRpb24uYWRkXCJcclxuICAgICAgKSB7XHJcbiAgICAgICAgcmV0dXJuO1xyXG4gICAgICB9XHJcbiAgICAgIGNhbGxiYWNrKGV2IGFzIEN1c3RvbVJld2FyZFJlZGVtcHRpb25FdmVudCk7XHJcbiAgICB9KTtcclxuICB9XHJcblxyXG4gIC8qKlxyXG4gICAqIExpc3RlbiBmb3IgbmV3IGZvbGxvdyBldmVudHNcclxuICAgKiBAcGFyYW0gY2FsbGJhY2sgRnVuY3Rpb24gdG8gY2FsbCB3aGVuIHNvbWVvbmUgZm9sbG93cyB0aGUgY2hhbm5lbFxyXG4gICAqL1xyXG4gIG9uTmV3Rm9sbG93KGNhbGxiYWNrOiAobWVzc2FnZTogRm9sbG93RXZlbnQpID0+IHZvaWQpIHtcclxuICAgIHJldHVybiB0aGlzLm9uRXZlbnRTdWJFdmVudCgoZXY6IEV2ZW50U3ViVW5rbm93bkV2ZW50KSA9PiB7XHJcbiAgICAgIGlmIChldi5zdWJzY3JpcHRpb24udHlwZSAhPT0gXCJjaGFubmVsLmZvbGxvd1wiKSB7XHJcbiAgICAgICAgcmV0dXJuO1xyXG4gICAgICB9XHJcbiAgICAgIGNhbGxiYWNrKGV2IGFzIEZvbGxvd0V2ZW50KTtcclxuICAgIH0pO1xyXG4gIH1cclxuXHJcbiAgLyoqXHJcbiAgICogTGlzdGVuIGZvciBuZXcgc3Vic2NyaXB0aW9uc1xyXG4gICAqIEBwYXJhbSBjYWxsYmFjayBGdW5jdGlvbiB0byBjYWxsIHdoZW4gc29tZW9uZSBzdWJzY3JpYmVzIGZvciB0aGUgZmlyc3QgdGltZVxyXG4gICAqL1xyXG4gIG9uTmV3U3Vic2NyaXB0aW9uKGNhbGxiYWNrOiAobWVzc2FnZTogU3Vic2NyaXB0aW9uRXZlbnQpID0+IHZvaWQpIHtcclxuICAgIHJldHVybiB0aGlzLm9uRXZlbnRTdWJFdmVudCgoZXY6IEV2ZW50U3ViVW5rbm93bkV2ZW50KSA9PiB7XHJcbiAgICAgIGlmIChldi5zdWJzY3JpcHRpb24udHlwZSAhPT0gXCJjaGFubmVsLnN1YnNjcmliZVwiKSB7XHJcbiAgICAgICAgcmV0dXJuO1xyXG4gICAgICB9XHJcbiAgICAgIGNhbGxiYWNrKGV2IGFzIFN1YnNjcmlwdGlvbkV2ZW50KTtcclxuICAgIH0pO1xyXG4gIH1cclxuXHJcbiAgLyoqXHJcbiAgICogTGlzdGVuIGZvciBnaWZ0ZWQgc3Vic2NyaXB0aW9uc1xyXG4gICAqIEBwYXJhbSBjYWxsYmFjayBGdW5jdGlvbiB0byBjYWxsIHdoZW4gc29tZW9uZSBnaWZ0cyBhIHN1YnNjcmlwdGlvblxyXG4gICAqL1xyXG4gIG9uR2lmdGVkU3Vic2NyaXB0aW9uKGNhbGxiYWNrOiAobWVzc2FnZTogU3Vic2NyaXB0aW9uR2lmdEV2ZW50KSA9PiB2b2lkKSB7XHJcbiAgICByZXR1cm4gdGhpcy5vbkV2ZW50U3ViRXZlbnQoKGV2OiBFdmVudFN1YlVua25vd25FdmVudCkgPT4ge1xyXG4gICAgICBpZiAoZXYuc3Vic2NyaXB0aW9uLnR5cGUgIT09IFwiY2hhbm5lbC5zdWJzY3JpcHRpb24uZ2lmdFwiKSB7XHJcbiAgICAgICAgcmV0dXJuO1xyXG4gICAgICB9XHJcbiAgICAgIGNhbGxiYWNrKGV2IGFzIFN1YnNjcmlwdGlvbkdpZnRFdmVudCk7XHJcbiAgICB9KTtcclxuICB9XHJcblxyXG4gIC8qKlxyXG4gICAqIExpc3RlbiBmb3IgcmV0dXJuaW5nIHN1YnNjcmlwdGlvbnNcclxuICAgKiBAcGFyYW0gY2FsbGJhY2sgRnVuY3Rpb24gdG8gY2FsbCB3aGVuIHNvbWVvbmUgcmVuZXdzIHRoZWlyIHN1YnNjcmlwdGlvblxyXG4gICAqL1xyXG4gIG9uUmVzdWJzY3JpcHRpb24oY2FsbGJhY2s6IChtZXNzYWdlOiBSZXN1YnNjcmlwdGlvbkV2ZW50KSA9PiB2b2lkKSB7XHJcbiAgICByZXR1cm4gdGhpcy5vbkV2ZW50U3ViRXZlbnQoKGV2OiBFdmVudFN1YlVua25vd25FdmVudCkgPT4ge1xyXG4gICAgICBpZiAoZXYuc3Vic2NyaXB0aW9uLnR5cGUgIT09IFwiY2hhbm5lbC5zdWJzY3JpcHRpb24ubWVzc2FnZVwiKSB7XHJcbiAgICAgICAgcmV0dXJuO1xyXG4gICAgICB9XHJcbiAgICAgIGNhbGxiYWNrKGV2IGFzIFJlc3Vic2NyaXB0aW9uRXZlbnQpO1xyXG4gICAgfSk7XHJcbiAgfVxyXG5cclxuICAvKipcclxuICAgKiBMaXN0ZW4gZm9yIGNoYW5uZWwgdXBkYXRlc1xyXG4gICAqIEBwYXJhbSBjYWxsYmFjayBGdW5jdGlvbiB0byBjYWxsIHdoZW4gY2hhbm5lbCBpbmZvIChuYW1lLCBnYW1lLCB0YWdzIGV0YykgaXMgY2hhbmdlZFxyXG4gICAqL1xyXG4gIG9uQ2hhbm5lbFVwZGF0ZShjYWxsYmFjazogKG1lc3NhZ2U6IENoYW5uZWxVcGRhdGVFdmVudCkgPT4gdm9pZCkge1xyXG4gICAgcmV0dXJuIHRoaXMub25FdmVudFN1YkV2ZW50KChldjogRXZlbnRTdWJVbmtub3duRXZlbnQpID0+IHtcclxuICAgICAgaWYgKGV2LnN1YnNjcmlwdGlvbi50eXBlICE9PSBcImNoYW5uZWwudXBkYXRlXCIpIHtcclxuICAgICAgICByZXR1cm47XHJcbiAgICAgIH1cclxuICAgICAgY2FsbGJhY2soZXYgYXMgQ2hhbm5lbFVwZGF0ZUV2ZW50KTtcclxuICAgIH0pO1xyXG4gIH1cclxuXHJcbiAgLyoqXHJcbiAgICogTGlzdGVuIGZvciB2aWV3ZXJzIGNoZWVyaW5nXHJcbiAgICogQHBhcmFtIGNhbGxiYWNrIEZ1bmN0aW9uIHRvIGNhbGwgd2hlbiBzb21lb25lIGNoZWVycyBzb21lIGJpdHNcclxuICAgKi9cclxuICBvbkNoZWVyKGNhbGxiYWNrOiAobWVzc2FnZTogQ2hlZXJFdmVudCkgPT4gdm9pZCkge1xyXG4gICAgcmV0dXJuIHRoaXMub25FdmVudFN1YkV2ZW50KChldjogRXZlbnRTdWJVbmtub3duRXZlbnQpID0+IHtcclxuICAgICAgaWYgKGV2LnN1YnNjcmlwdGlvbi50eXBlICE9PSBcImNoYW5uZWwuY2hlZXJcIikge1xyXG4gICAgICAgIHJldHVybjtcclxuICAgICAgfVxyXG4gICAgICBjYWxsYmFjayhldiBhcyBDaGVlckV2ZW50KTtcclxuICAgIH0pO1xyXG4gIH1cclxuXHJcbiAgLyoqXHJcbiAgICogTGlzdGVuIGZvciBpbmNvbWluZyByYWlkc1xyXG4gICAqIEBwYXJhbSBjYWxsYmFjayBGdW5jdGlvbiB0byBjYWxsIHdoZW4gc29tZW9uZSByYWlkcyB0aGUgY2hhbm5lbFxyXG4gICAqL1xyXG4gIG9uUmFpZChjYWxsYmFjazogKG1lc3NhZ2U6IFJhaWRFdmVudCkgPT4gdm9pZCkge1xyXG4gICAgcmV0dXJuIHRoaXMub25FdmVudFN1YkV2ZW50KChldjogRXZlbnRTdWJVbmtub3duRXZlbnQpID0+IHtcclxuICAgICAgaWYgKGV2LnN1YnNjcmlwdGlvbi50eXBlICE9PSBcImNoYW5uZWwucmFpZFwiKSB7XHJcbiAgICAgICAgcmV0dXJuO1xyXG4gICAgICB9XHJcbiAgICAgIGNhbGxiYWNrKGV2IGFzIFJhaWRFdmVudCk7XHJcbiAgICB9KTtcclxuICB9XHJcbn1cclxuXHJcbmV4cG9ydCBjbGFzcyBUd2l0Y2gge1xyXG4gIC8qKlxyXG4gICAqIFR3aXRjaCBjaGF0IHJlbGF0ZWQgZnVuY3Rpb25zXHJcbiAgICovXHJcbiAgY2hhdDogQ2hhdDtcclxuXHJcbiAgLyoqXHJcbiAgICogRXZlbnQgcmVsYXRlZCBmdW5jdGlvbnNcclxuICAgKi9cclxuICBldmVudDogRXZlbnRTdWI7XHJcblxyXG4gIGNvbnN0cnVjdG9yKGt2OiBLaWxvdm9sdCkge1xyXG4gICAgdGhpcy5jaGF0ID0gbmV3IENoYXQoa3YpO1xyXG4gICAgdGhpcy5ldmVudCA9IG5ldyBFdmVudFN1Yihrdik7XHJcbiAgfVxyXG59XHJcbiIsImltcG9ydCB7IEtpbG92b2x0IH0gZnJvbSBcImh0dHBzOi8vZGVuby5sYW5kL3gva2lsb3ZvbHRAdjguMC4wL21vZC50c1wiO1xyXG5pbXBvcnQgeyBSZWRlZW0gfSBmcm9tIFwiLi90eXBlcy50c1wiO1xyXG5cclxuZXhwb3J0IGNsYXNzIExveWFsdHkge1xyXG4gIC8qKlxyXG4gICAqIExpc3RlbiBmb3IgcmVkZWVtc1xyXG4gICAqIEBwYXJhbSBjYWxsYmFjayBGdW5jdGlvbiB0byBjYWxsIHdoZW4gc29tZW9uZSByZWRlZW1zIGEgcmV3YXJkXHJcbiAgICovXHJcbiAgb25SZWRlZW0oY2FsbGJhY2s6IChtZXNzYWdlOiBSZWRlZW0pID0+IHZvaWQpIHtcclxuICAgIHJldHVybiB0aGlzLmt2LnN1YnNjcmliZUtleShcImxveWFsdHkvZXYvbmV3LXJlZGVlbVwiLCAobmV3VmFsdWU6IHN0cmluZykgPT4ge1xyXG4gICAgICBjb25zdCBtZXNzYWdlID0gSlNPTi5wYXJzZShuZXdWYWx1ZSkgYXMgUmVkZWVtO1xyXG4gICAgICBjYWxsYmFjayhtZXNzYWdlKTtcclxuICAgIH0pO1xyXG4gIH1cclxuXHJcbiAgY29uc3RydWN0b3IocHJpdmF0ZSByZWFkb25seSBrdjogS2lsb3ZvbHQpIHt9XHJcbn1cclxuIiwiaW1wb3J0IHsgS2lsb3ZvbHQgfSBmcm9tIFwiaHR0cHM6Ly9kZW5vLmxhbmQveC9raWxvdm9sdEB2OC4wLjAvbW9kLnRzXCI7XG5pbXBvcnQgeyBUd2l0Y2ggfSBmcm9tIFwiLi90d2l0Y2gvdHdpdGNoLnRzXCI7XG5pbXBvcnQgeyBMb3lhbHR5IH0gZnJvbSBcIi4vbG95YWx0eS9sb3lhbHR5LnRzXCI7XG5cbmV4cG9ydCBpbnRlcmZhY2UgQ2xpZW50T3B0aW9ucyB7XG4gIC8qIEFkZHJlc3MgdG8gY29ubmVjdCB0byAoaW5jbHVkaW5nIHBhdGgpLCBhIGRlZmF1bHQgd2lsbCBiZSB1c2VkIGlmIHRoaXMgaXMgbm90IHNwZWNpZmllZCAqL1xuICBhZGRyZXNzPzogc3RyaW5nO1xuXG4gIC8qIElmIHByb3ZpZGVkLCBhdXRoZW50aWNhdGUgbm9uLWludGVyYWN0aXZlbHkgYXMgc29vbiBhcyBjb25uZWN0aW9uIGlzIGVzdGFibGlzaGVkICovXG4gIHBhc3N3b3JkPzogc3RyaW5nO1xuXG4gIC8qIElmIHRydWUsIGF1dGhlbnRpY2F0ZSBpbnRlcmFjdGl2ZWx5IGFzIHNvb24gYXMgY29ubmVjdGlvbiBpcyBlc3RhYmxpc2hlZCAqL1xuICBpbnRlcmFjdGl2ZT86IGJvb2xlYW47XG5cbiAgLyogV2hlbiBhdXRoZW50aWNhdGluZyBpbnRlcmFjdGl2ZWx5LCB0aGlzIGRhdGEgaXMgYWRkZWQgdG8gdGhlIGF1dGggbWVzc2FnZSAqL1xuICBpbnRlcmFjdGl2ZURhdGE/OiBSZWNvcmQ8c3RyaW5nLCB1bmtub3duPjtcbn1cblxuLyoqXG4gKiBTdHJpbWVydMO8bCBjbGllbnRcbiAqL1xuZXhwb3J0IGRlZmF1bHQgY2xhc3MgU3RyaW1lcnR1bCB7XG4gIHByaXZhdGUga3Y6IEtpbG92b2x0O1xuXG4gIC8qKlxuICAgKiBUd2l0Y2gtcmVsYXRlZCBmdW5jdGlvbnNcbiAgICovXG4gIHR3aXRjaDogVHdpdGNoO1xuXG4gIC8qKlxuICAgKiBMb3lhbHR5IHN5c3RlbSBmdW5jdGlvbnNcbiAgICovXG4gIGxveWFsdHk6IExveWFsdHk7XG5cbiAgLyoqXG4gICAqIENyZWF0ZSBhIG5ldyBzdHJpbWVydHVsIGNsaWVudFxuICAgKiBAcGFyYW0gb3B0aW9ucyBDb25uZWN0aW9uIG9wdGlvbnMgZm9yIGF1dGhlbnRpY2F0aW9uXG4gICAqL1xuICBjb25zdHJ1Y3RvcihvcHRpb25zOiBDbGllbnRPcHRpb25zKSB7XG4gICAgdGhpcy5rdiA9IG5ldyBLaWxvdm9sdChvcHRpb25zLmFkZHJlc3MgfHwgXCJ3czovL2xvY2FsaG9zdDo0MzM3L3dzXCIsIHtcbiAgICAgIHJlY29ubmVjdDogdHJ1ZSxcbiAgICAgIC4uLm9wdGlvbnMsXG4gICAgfSk7XG4gICAgdGhpcy50d2l0Y2ggPSBuZXcgVHdpdGNoKHRoaXMua3YpO1xuICAgIHRoaXMubG95YWx0eSA9IG5ldyBMb3lhbHR5KHRoaXMua3YpO1xuICB9XG5cbiAgLyoqXG4gICAqIENvbm5lY3RzIHRvIHRoZSBzdHJpbWVydMO8bCBpbnN0YW5jZS4gWW91IG11c3QgY2FsbCBhbmQgYXdhaXQgdGhpcyBiZWZvcmVcbiAgICogdXNpbmcgYW55IG9mIHRoZSBvdGhlciBtZXRob2RzIVxuICAgKi9cbiAgY29ubmVjdCgpIHtcbiAgICByZXR1cm4gdGhpcy5rdi5jb25uZWN0KCk7XG4gIH1cbn1cbiJdLCJuYW1lcyI6W10sIm1hcHBpbmdzIjoiQUFBQSxNQUFNLGNBQ0o7QUFDRixNQUFNLFdBQVc7T0FBSTtDQUFZO0FBRzFCLFNBQVMsaUJBQWlCLEdBQVcsRUFBRTtJQUM1QyxNQUFNLFNBQVMsRUFBRTtJQUVqQixJQUFLLElBQUksSUFBSSxHQUFHLElBQUksSUFBSSxNQUFNLEdBQUcsR0FBRyxJQUFLO1FBQ3ZDLE1BQU0sUUFBUTtlQUFJLElBQUksS0FBSyxDQUFDLElBQUksR0FBRyxJQUFJLElBQUk7U0FBRztRQUM5QyxNQUFNLE1BQU0sTUFDVCxHQUFHLENBQUMsQ0FBQyxJQUFNLFNBQVMsT0FBTyxDQUFDLEdBQUcsUUFBUSxD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
