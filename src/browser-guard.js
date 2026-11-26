"use strict";

const crypto = require("node:crypto");

const pkgVersion = (() => {
  try {
    return require("../package.json").version || "2.1.0";
  } catch {
    return "2.1.0";
  }
})();

function serializeRulesForScript(raw) {
  return (Array.isArray(raw) ? raw : []).map((r) => {
    if (r instanceof RegExp) return { regex: r.source, flags: r.flags.replace(/[gy]/g, "") };
    return r;
  });
}

function escapeInlineJson(obj) {
  return JSON.stringify(obj)
    .replace(/</g, "\\u003c")
    .replace(/>/g, "\\u003e")
    .replace(/&/g, "\\u0026")
    .replace(/[\u0080-\uffff]/g, (ch) => "\\u" + ch.charCodeAt(0).toString(16).padStart(4, "0"));
}

function extractMarkedSlice(source, startMarker, endMarker) {
  const s = source.indexOf(startMarker);
  if (s < 0) return "";
  const from = s + startMarker.length;
  const e = source.indexOf(endMarker, from);
  if (e < 0) return "";
  return source.slice(from, e);
}

function compactGeneratedJs(src) {
  const lines = String(src || "").split("\n");
  const out = [];
  for (let i = 0; i < lines.length; i++) {
    const trimmed = lines[i].trim();
    if (!trimmed || trimmed.startsWith("//")) continue;
    out.push(trimmed);
  }
  return out.join("\n");
}

/**
 * Computes the deterministic Subresource Integrity (`sha384-...`) digest, 12-char content
 * cache-busting version, and runtime `guardHash` (`sha256` hex covering the ENTIRE
 * `__psGuardMain` closure — including `SERVER_ECDSA_PUB`, config flags, intrinsic capture,
 * SubtleCrypto checks, CDP/console-eval detection, handshake, fetch/XHR wrappers & export lock).
 */
function computeGuardIntegrity(scriptSource) {
  const src = String(scriptSource || "");
  const sri = `sha384-${crypto.createHash("sha384").update(src, "utf8").digest("base64")}`;
  const version = crypto.createHash("sha256").update(src, "utf8").digest("hex").slice(0, 12);
  const mainSlice = extractMarkedSlice(src, "/*__PS_GUARD_MAIN_START__*/", "/*__PS_GUARD_MAIN_END__*/");
  const norm = mainSlice.replace(/\s+/g, " ").trim();
  const guardHash = crypto.createHash("sha256").update(norm, "utf8").digest("hex");
  return { sri, version, guardHash };
}

/**
 * Generates the zero-dependency browser guard served at `/__proxysnare/guard.js`.
 */
function buildBrowserGuardScript({
  basePath = "/__proxysnare",
  mode = "strict",
  protectedPaths = ["/api"],
  protectedRules = null,
  initialBoot = null,
  serverVerifyPubB64 = "",
  userGestureWindowMs = 15_000,
  requireVeilBreak = false,
  allowDevTools = false,
  blockCdpActive = !allowDevTools,
  blockConsoleEval = true,
  collectConsoleEvalTelemetry = (blockConsoleEval || !allowDevTools),
  requireGuardIntegrity = true,
  failClosedOnTamper = true,
  embeddedVeilBreakScript = "",
} = {}) {
  const normBase = String(basePath || "/__proxysnare").replace(/\/+$/, "") || "/__proxysnare";
  const rawMode = String(mode || "strict").trim().toLowerCase();
  const normMode = rawMode === "observe" ? "monitor" : rawMode;
  const bootJson = escapeInlineJson(initialBoot || null);
  const verJson = escapeInlineJson(pkgVersion);
  if (normMode === "off") {
    return compactGeneratedJs(`(() => {
  "use strict";
  const INITIAL_BOOT_INLINE = ${bootJson};
  /*__PS_GUARD_MAIN_START__*/function __psGuardMain() {
    if (typeof window === "undefined") return;
    const psApi = Object.freeze({
      ready: () => Promise.resolve(true),
      detectCdpActive: () => false,
      guardHash: () => "OFF",
      version: ${verJson},
      mode: "off",
    });
    try {
      Object.defineProperty(window, "ProxySnare", { value: psApi, writable: false, enumerable: true, configurable: false });
    } catch (_) {}
  }/*__PS_GUARD_MAIN_END__*/
  __psGuardMain(INITIAL_BOOT_INLINE);
})();
`);
  }
  const rules = serializeRulesForScript(
    Array.isArray(protectedRules) && protectedRules.length > 0 ? protectedRules : protectedPaths
  );
  const rulesJson = escapeInlineJson(rules);
  const bpJson = escapeInlineJson(normBase);
  const pubJson = escapeInlineJson(String(serverVerifyPubB64 || ""));
  const ugWin = Number.isFinite(userGestureWindowMs) && userGestureWindowMs > 0 ? Math.round(userGestureWindowMs) : 15_000;
  const reqVbJson = escapeInlineJson(Boolean(requireVeilBreak));
  const allowDtJson = escapeInlineJson(Boolean(allowDevTools));
  const blockCdpJson = escapeInlineJson(Boolean(blockCdpActive));
  const blockCeJson = escapeInlineJson(Boolean(blockConsoleEval));
  const collectCeJson = escapeInlineJson(Boolean(collectConsoleEvalTelemetry));
  const reqGiJson = escapeInlineJson(Boolean(requireGuardIntegrity));
  const failClosedTamperJson = escapeInlineJson(Boolean(failClosedOnTamper));
  const isMonitorJson = escapeInlineJson(normMode === "monitor");
  const hasEmbeddedVb = typeof embeddedVeilBreakScript === "string" && embeddedVeilBreakScript.trim().length > 0;
  const embeddedVbJson = escapeInlineJson(hasEmbeddedVb);
  const embeddedVbBlock = hasEmbeddedVb
    ? `\n    // Private lexical closure embedding VeilBreak SDK (unreachable from window / Symbol.for / MutationObserver)\n    ${embeddedVeilBreakScript.trim()}\n`
    : "";

  return compactGeneratedJs(`(() => {
  "use strict";
  const INITIAL_BOOT_INLINE = ${bootJson};
  /*__PS_GUARD_MAIN_START__*/function __psGuardMain(INITIAL_BOOT_ARG) {
    if (typeof window === "undefined") return;

    // Capture native intrinsics, constructors, prototypes & well-known Symbols before any page/DevTools script can overwrite them
    const _Object = Object;
    const _objProto = _Object.prototype;
    const _Array = Array;
    const _arrProto = _Array.prototype;
    const _RegExp = RegExp;
    const _regExpProto = _RegExp.prototype;
    const _Function = Function;
    const _fnProto = _Function.prototype;
    const _Reflect = Reflect;
    const _Date = Date;
    const _Math = Math;
    const _JSON = JSON;
    const _Symbol = typeof Symbol === "function" ? Symbol : null;
    const _symSpecies = _Symbol ? _Symbol.species : null;
    const _symIterator = _Symbol ? _Symbol.iterator : null;
    const _symReplace = _Symbol ? _Symbol.replace : null;
    const _symSplit = _Symbol ? _Symbol.split : null;
    const _symMatch = _Symbol ? _Symbol.match : null;
    const _ArrayBuffer = typeof ArrayBuffer === "function" ? ArrayBuffer : null;
    const _arrayBufferProto = _ArrayBuffer ? _ArrayBuffer.prototype : null;
    const _CryptoKey = typeof CryptoKey === "function" ? CryptoKey : null;
    const _cryptoKeyProto = _CryptoKey ? _CryptoKey.prototype : null;
    const _Error = Error;
    const _String = String;
    const _NativePromise = Promise;
    const _nativePromiseThen = _NativePromise.prototype.then;
    const _Uint8Array = Uint8Array;
    const _Int32Array = Int32Array;
    const _MathRound = _Math.round;
    const _MathMin = _Math.min;
    const _MathMax = _Math.max;
    const _MathFloor = _Math.floor;
    const _MathClz32 = _Math.clz32;
    const _reflectApply = _Reflect.apply;
    const _fnCall = _fnProto.call;
    const _fnApply = _fnProto.apply;
    const _fnBind = _fnProto.bind;
    const _defineProperty = _Object.defineProperty;
    const _objCreate = _Object.create;
    const _defData = (obj, k, val, writable, configurable, enumerable) => {
      const d = _objCreate(null);
      d.value = val;
      if (writable !== undefined) d.writable = writable;
      if (configurable !== undefined) d.configurable = configurable;
      if (enumerable !== undefined) d.enumerable = enumerable;
      return _defineProperty(obj, k, d);
    };
    const _defGet = (obj, k, getter, configurable) => {
      const d = _objCreate(null);
      d.get = getter;
      if (configurable !== undefined) d.configurable = configurable;
      return _defineProperty(obj, k, d);
    };
    const _copyNullDesc = (src) => {
      const d = _objCreate(null);
      if ("enumerable" in src) d.enumerable = src.enumerable;
      if ("configurable" in src) d.configurable = src.configurable;
      if ("get" in src || "set" in src) {
        if ("get" in src) d.get = src.get;
        if ("set" in src) d.set = src.set;
      } else {
        if ("value" in src) d.value = src.value;
        if ("writable" in src) d.writable = src.writable;
      }
      return d;
    };
    const _getOwnPropertyNames = _Object.getOwnPropertyNames;
    const _getOwnPropDesc = _Object.getOwnPropertyDescriptor;
    const _getProto = _Object.getPrototypeOf;
    const _isFrozen = _Object.isFrozen;
    const _hasOwn = _objProto.hasOwnProperty;
    const _fnToString = _fnProto.toString;
    const _regexTest = _regExpProto.test;
    const _regexExec = _regExpProto.exec;
    const _regexSymReplace = _symReplace ? _regExpProto[_symReplace] : null;
    const _promiseSpeciesGet = _symSpecies ? (_getOwnPropDesc(_NativePromise, _symSpecies)?.get || null) : null;
    const _arrayIter = _symIterator ? _arrProto[_symIterator] : null;
    const _isArray = _Array.isArray;
    const _arrayValues = _arrProto.values;
    const _arrIterProto = _arrayValues ? (() => { try { return _getProto(_reflectApply(_arrayValues, [], [])); } catch (_) { return null; } })() : null;
    const _arrIterNext = _arrIterProto && typeof _arrIterProto.next === "function" ? _arrIterProto.next : null;
    const _strProto = _getProto("");
    const _strSplit = _strProto.split;
    const _strIncludes = _strProto.includes;
    const _strReplace = _strProto.replace;
    const _strTrim = _strProto.trim;
    const _strStartsWith = _strProto.startsWith;
    const _strEndsWith = _strProto.endsWith;
    const _strToLower = _strProto.toLowerCase;
    const _strToUpper = _strProto.toUpperCase;
    const _strCharCodeAt = _strProto.charCodeAt;
    const _strCharAt = _strProto.charAt;
    const _strSlice = _strProto.slice;
    const _strIndexOf = _strProto.indexOf;
    const _strLastIndexOf = _strProto.lastIndexOf;
    const rxTest = (re, s) => _reflectApply(_regexExec, re, [s]) !== null;
    const _URL = URL;
    const _urlProto = _URL && _URL.prototype ? _URL.prototype : null;
    const _urlOriginGet = _urlProto ? (_getOwnPropDesc(_urlProto, "origin")?.get || null) : null;
    const _urlPathnameGet = _urlProto ? (_getOwnPropDesc(_urlProto, "pathname")?.get || null) : null;
    const _EMPTY_U8 = new _Uint8Array(0);
    const _SymbolFor = _Symbol && typeof _Symbol.for === "function" ? _Symbol.for : null;
    const _TextEncoder = typeof TextEncoder === "function" ? TextEncoder : null;
    const _textEncoder = new TextEncoder();
    const _encode = _TextEncoder && _TextEncoder.prototype ? _TextEncoder.prototype.encode : null;
    const _encodeUtf8 = (s) => (_encode ? _reflectApply(_encode, _textEncoder, [_String(s)]) : _textEncoder.encode(_String(s)));
    const _textDecoder = typeof TextDecoder === "function" ? new TextDecoder() : null;
    const _decodeUtf8 = _textDecoder && TextDecoder.prototype ? TextDecoder.prototype.decode : null;
    const _jsonStringify = _JSON.stringify;
    const _jsonParse = _JSON.parse;
    const _Headers = typeof Headers === "function" ? Headers : null;
    const _hdrSet = _Headers && _Headers.prototype ? _Headers.prototype.set : null;
    const _hdrGet = _Headers && _Headers.prototype ? _Headers.prototype.get : null;
    const _hdrHas = _Headers && _Headers.prototype ? _Headers.prototype.has : null;
    const _Response = typeof Response === "function" ? Response : null;
    const _RespProto = _Response && _Response.prototype ? _Response.prototype : null;
    const _ResponseJson = _RespProto && typeof _RespProto.json === "function" ? _RespProto.json : null;
    const _respClone = _RespProto && typeof _RespProto.clone === "function" ? _RespProto.clone : null;
    const _respArrayBuffer = _RespProto && typeof _RespProto.arrayBuffer === "function" ? _RespProto.arrayBuffer : null;
    const _respStatusGet = _RespProto ? (_getOwnPropDesc(_RespProto, "status")?.get || null) : null;
    const _respHeadersGet = _RespProto ? (_getOwnPropDesc(_RespProto, "headers")?.get || null) : null;
    const _respRedirectedGet = _RespProto ? (_getOwnPropDesc(_RespProto, "redirected")?.get || null) : null;
    const _respUrlGet = _RespProto ? (_getOwnPropDesc(_RespProto, "url")?.get || null) : null;
    const _respTypeGet = _RespProto ? (_getOwnPropDesc(_RespProto, "type")?.get || null) : null;
    const _rawFetch = typeof window.fetch === "function" ? window.fetch : null;
    const origFetch = _rawFetch ? _reflectApply(_fnBind, _rawFetch, [window]) : null;
    const _getRandomValues =
      typeof Crypto !== "undefined" && Crypto.prototype && typeof Crypto.prototype.getRandomValues === "function"
        ? Crypto.prototype.getRandomValues
        : (typeof crypto !== "undefined" && typeof crypto.getRandomValues === "function" ? crypto.getRandomValues : null);
    const _perfGetEntriesByType =
      typeof Performance !== "undefined" && Performance.prototype && typeof Performance.prototype.getEntriesByType === "function"
        ? Performance.prototype.getEntriesByType
        : (typeof performance !== "undefined" && typeof performance.getEntriesByType === "function" ? performance.getEntriesByType : null);
    const hasXhr = typeof XMLHttpRequest !== "undefined";
    const OrigXHR = hasXhr ? XMLHttpRequest : null;
    const _XhrProto = hasXhr ? XMLHttpRequest.prototype : null;
    const origOpen = _XhrProto ? _XhrProto.open : null;
    const origSend = _XhrProto ? _XhrProto.send : null;
    const origAbort = _XhrProto ? _XhrProto.abort : null;
    const origSetHdr = _XhrProto ? _XhrProto.setRequestHeader : null;
    const origOverrideMime = _XhrProto ? _XhrProto.overrideMimeType : null;
    const _xhrReadyStateGet = _XhrProto ? (_getOwnPropDesc(_XhrProto, "readyState")?.get || null) : null;
    const _xhrStatusGet = _XhrProto ? (_getOwnPropDesc(_XhrProto, "status")?.get || null) : null;
    const _xhrResponseUrlGet = _XhrProto ? (_getOwnPropDesc(_XhrProto, "responseURL")?.get || null) : null;
    const _xhrGetRespHdr = _XhrProto && typeof _XhrProto.getResponseHeader === "function" ? _XhrProto.getResponseHeader : null;
    const readRespStatus = (r) => (_respStatusGet ? _reflectApply(_respStatusGet, r, []) : r.status);
    const readRespHeaders = (r) => (_respHeadersGet ? _reflectApply(_respHeadersGet, r, []) : r.headers);
    const readRespRedirected = (r) => (_respRedirectedGet ? _reflectApply(_respRedirectedGet, r, []) : r.redirected);
    const readRespUrl = (r) => (_respUrlGet ? _reflectApply(_respUrlGet, r, []) : r.url);
    const readRespType = (r) => (_respTypeGet ? _reflectApply(_respTypeGet, r, []) : r.type);
    const readHdr = (h, k) => (h ? (_hdrGet ? _reflectApply(_hdrGet, h, [k]) : h.get(k)) : null);
    const readRespCloneJson = (r) => {
      const c = _respClone ? _reflectApply(_respClone, r, []) : r.clone();
      return _ResponseJson ? _reflectApply(_ResponseJson, c, []) : c.json();
    };
    const readXhrReadyState = (x) => (_xhrReadyStateGet ? _reflectApply(_xhrReadyStateGet, x, []) : x.readyState);
    const readXhrStatus = (x) => (_xhrStatusGet ? _reflectApply(_xhrStatusGet, x, []) : x.status);
    const readXhrResponseUrl = (x) => (_xhrResponseUrlGet ? _reflectApply(_xhrResponseUrlGet, x, []) : x.responseURL);
    const readXhrRespHdr = (x, k) => (_xhrGetRespHdr ? _reflectApply(_xhrGetRespHdr, x, [k]) : x.getResponseHeader(k));
    const _Document = typeof Document === "function" ? Document : null;
    const _Node = typeof Node === "function" ? Node : null;
    const _HTMLIFrameElement = typeof HTMLIFrameElement === "function" ? HTMLIFrameElement : null;
    const _iframeProto = _HTMLIFrameElement ? _HTMLIFrameElement.prototype : null;
    const _Element = typeof Element === "function" ? Element : null;
    const _docCreateElement = _Document && _Document.prototype ? _Document.prototype.createElement : null;
    const _nodeAppendChild = _Node && _Node.prototype ? _Node.prototype.appendChild : null;
    const _docElGet = _Document && _Document.prototype ? (_getOwnPropDesc(_Document.prototype, "documentElement")?.get || null) : null;
    const _iframeCwGet = _iframeProto ? (_getOwnPropDesc(_iframeProto, "contentWindow")?.get || null) : null;
    const _elGetAttr = _Element && _Element.prototype ? _Element.prototype.getAttribute : null;
    const _elAttachShadow = _Element && _Element.prototype && typeof _Element.prototype.attachShadow === "function" ? _Element.prototype.attachShadow : null;
    const _elRemove = _Element && _Element.prototype && typeof _Element.prototype.remove === "function" ? _Element.prototype.remove : null;
    const _errProtoStackGet = _Error && _Error.prototype ? (_getOwnPropDesc(_Error.prototype, "stack")?.get || null) : null;
    const _errInstStackGet = !_errProtoStackGet ? (_getOwnPropDesc(new _Error(), "stack")?.get || null) : null;
    const _errStackGet = _errProtoStackGet || _errInstStackGet;
    const _hasInitialStackTraceLimit = "stackTraceLimit" in _Error;
    // Detect V8's leading "Error" stack header AND capture native V8 CallSite.prototype methods inside a unified
    // save/restore block so pre-existing writable/configurable Error.prepareStackTrace formatters (e.g. source-map-support, Bluebird)
    // neither break V8 detection (false-positive TAMPERED_GUARD) nor get overwritten!
    const _capSites = (_, sites) => sites;
    let _hasV8ErrorHeader = false;
    let _callSiteCaptureTampered = false;
    let _callSiteProto = null;
    let _csGetFileName = null;
    let _csGetSrcUrl = null;
    let _csIsEval = null;
    let _csIsNative = null;
    let _csIsPromiseAll = null;
    let _csGetFnName = null;
    let _csToString = null;
    (() => {
      const checkV8Header = () => {
        try {
          const pe = new _Error();
          _defData(pe, "name", "Error", true, true);
          _defData(pe, "message", "", true, true);
          const st = _errStackGet ? _reflectApply(_errStackGet, pe, []) : pe.stack;
          if (typeof st !== "string" || !st) return false;
          const nl = _reflectApply(_strIndexOf, st, ["\\n"]);
          const first = nl >= 0 ? _reflectApply(_strSlice, st, [0, nl]) : st;
          return _reflectApply(_strTrim, first, []) === "Error";
        } catch (_) {
          return false;
        }
      };
      if (_errProtoStackGet) {
        _hasV8ErrorHeader = checkV8Header();
        return;
      }
      try {
        const pDesc0 = _getOwnPropDesc(_Error, "prepareStackTrace");
        const pInh0 = !pDesc0 && ("prepareStackTrace" in _Error);
        const pLocked0 = Boolean(pInh0 || (pDesc0 && !pDesc0.configurable && (!pDesc0.writable || pDesc0.get || pDesc0.set)));
        const stlDesc0 = _getOwnPropDesc(_Error, "stackTraceLimit");
        const stlInh0 = _hasInitialStackTraceLimit && !stlDesc0 && ("stackTraceLimit" in _Error);
        const stlAcc0 = Boolean(stlDesc0 && (stlDesc0.get || stlDesc0.set));
        const stlVal0 = typeof _Error.stackTraceLimit === "number" ? _Error.stackTraceLimit : NaN;
        const stlLocked0 = Boolean(stlInh0 || (stlDesc0 && !stlDesc0.configurable && (stlAcc0 || (!stlDesc0.writable && !(stlVal0 >= 2)))));
        if (pLocked0 || stlLocked0) {
          _hasV8ErrorHeader = checkV8Header();
          if (_hasV8ErrorHeader || pLocked0 || stlLocked0) _callSiteCaptureTampered = true;
          return;
        }
        let savedPst0;
        let clA0 = false;
        let clD0 = false;
        if (pDesc0) {
          if (pDesc0.writable && !pDesc0.get && !pDesc0.set) { savedPst0 = _Error.prepareStackTrace; clA0 = true; }
          else if (pDesc0.configurable) { clD0 = true; }
        }
        let savedStl0;
        let rStlA0 = false;
        let rStlD0 = false;
        try {
          if (_hasInitialStackTraceLimit && (!(stlVal0 >= 2) || stlAcc0)) {
            if (!stlDesc0 || (stlDesc0.writable && !stlAcc0)) {
              savedStl0 = _Error.stackTraceLimit;
              _Error.stackTraceLimit = 64;
              rStlA0 = true;
            } else if (stlDesc0.configurable) {
              _defData(_Error, "stackTraceLimit", 64, true, true);
              rStlD0 = true;
            }
          }
          if (clD0) _defData(_Error, "prepareStackTrace", undefined, true, true);
          else if (pDesc0) _Error.prepareStackTrace = undefined;
          _hasV8ErrorHeader = checkV8Header();
          if (_hasV8ErrorHeader) {
            if (clD0) _defData(_Error, "prepareStackTrace", _capSites, true, true);
            else _Error.prepareStackTrace = _capSites;
            const pe2 = new _Error();
            const rawSites0 = _errStackGet ? _reflectApply(_errStackGet, pe2, []) : pe2.stack;
            if (_isArray(rawSites0) && rawSites0.length > 0 && rawSites0[0] && typeof rawSites0[0] === "object") {
              const csp = _getProto(rawSites0[0]);
              if (csp && typeof csp.getFileName === "function" && typeof csp.isEval === "function") {
                _callSiteProto = csp;
                _csGetFileName = csp.getFileName;
                _csGetSrcUrl = typeof csp.getScriptNameOrSourceURL === "function" ? csp.getScriptNameOrSourceURL : null;
                _csIsEval = csp.isEval;
                _csIsNative = typeof csp.isNative === "function" ? csp.isNative : null;
                _csIsPromiseAll = typeof csp.isPromiseAll === "function" ? csp.isPromiseAll : null;
                _csGetFnName = typeof csp.getFunctionName === "function" ? csp.getFunctionName : null;
                _csToString = typeof csp.toString === "function" ? csp.toString : null;
              }
            }
            if (!_callSiteProto || !_csGetFileName || !_csIsEval) {
              _callSiteCaptureTampered = true;
            }
          }
        } finally {
          if (rStlA0) { try { _Error.stackTraceLimit = savedStl0; } catch (_) {} }
          else if (rStlD0) { try { _defineProperty(_Error, "stackTraceLimit", _copyNullDesc(stlDesc0)); } catch (_) {} }
          if (clA0) { try { _Error.prepareStackTrace = savedPst0; } catch (_) {} }
          else if (clD0) { try { _defineProperty(_Error, "prepareStackTrace", _copyNullDesc(pDesc0)); } catch (_) {} }
          else if (_hasV8ErrorHeader) { try { _Error.prepareStackTrace = undefined; } catch (_) {} }
        }
      } catch (_) {
        _callSiteCaptureTampered = true;
      }
    })();
    const _rawDateNow = Date.now;
    const _rawPerfNow =
      typeof Performance !== "undefined" && Performance.prototype && typeof Performance.prototype.now === "function"
        ? Performance.prototype.now
        : (typeof performance !== "undefined" && typeof performance.now === "function" ? performance.now : null);
    const _dateNow = () => _reflectApply(_rawDateNow, Date, []);
    const _perfNow = _rawPerfNow ? () => _reflectApply(_rawPerfNow, performance, []) : null;
    const monoNow = () => (_perfNow ? _perfNow() : _dateNow());
    // Single unified native-code regex pair (replaces ~87 per-method RegExp literals; immune to window.RegExp hooks & .bind(null)!)
    const _NATIVE_FN_RE = /^function\\s+(\\[Symbol\\.[A-Za-z]+\\]|[A-Za-z0-9_$]+)\\s*\\(\\s*\\)\\s*\\{\\s*\\[native code\\]\\s*\\}$/;
    const _NATIVE_GET_RE = /^function\\s+(?:get\\s+)?(\\[Symbol\\.[A-Za-z]+\\]|[A-Za-z0-9_$]+)\\s*\\(\\s*\\)\\s*\\{\\s*\\[native code\\]\\s*\\}$/;
    const _ERR_INST_STACK_GET_RE = /^function(?:\\s+(?:get\\s+)?stack)?\\s*\\(\\s*\\)\\s*\\{\\s*\\[native code\\]\\s*\\}$/;
    const _ARR_IDX_RE = /^(?:0|[1-9]\\d*)$/;
    const _WS_RE = /\\s/;
    const isNativeNamed = (fn, name, toStrFn = _fnToString, execFn = _regexExec, applyFn = _reflectApply, isGetter = false) => {
      if (typeof fn !== "function") return false;
      const m = applyFn(execFn, isGetter ? _NATIVE_GET_RE : _NATIVE_FN_RE, [applyFn(toStrFn, fn, [])]);
      return m !== null && m[1] === name;
    };
    const hasProtoIndexPollutionFast = () =>
      ("0" in _arrProto) || ("1" in _arrProto) || ("2" in _arrProto) || ("3" in _arrProto) || ("4" in _arrProto);
    const hasProtoIndexPollution = (getNamesFn = _getOwnPropertyNames, execFn = _regexExec, applyFn = _reflectApply) => {
      const ap = getNamesFn(_arrProto);
      for (let i = 0; i < ap.length; i++) {
        if (applyFn(execFn, _ARR_IDX_RE, [ap[i]]) !== null) return true;
      }
      const op = getNamesFn(_objProto);
      for (let i = 0; i < op.length; i++) {
        if (applyFn(execFn, _ARR_IDX_RE, [op[i]]) !== null) return true;
      }
      return false;
    };
    const _EXT_SCHEME_RE = /^(?:chrome|moz|safari(?:-web)?)-extension:\\/\\//i;
    const _EXEC_SCRIPT_TYPE_RE = /^(?:module|(?:text|application)\\/(?:javascript|ecmascript|x-javascript|x-ecmascript|livescript|jscript))$/i;
    const _LINE_COL_PAREN_RE = /:\\d+(?::\\d+)?\\)$/;
    const _SUS_AUTOMATION_RE = /^(\\$?cdc_|__playwright|__pw_manual|__pwInitScripts|__puppeteer|__webdriver|_selenium|_Selenium|__fxdriver|__driver_|domAutomation|callPhantom|_phantom|__nightmare|__lastWatir)/i;
    const _FAST_AUTOMATION_KEYS = [
      "__playwright", "__pw_manual", "__pwInitScripts", "__puppeteer_evaluation_script__",
      "__webdriver_evaluate", "__selenium_evaluate", "__webdriver_script_function",
      "__fxdriver_evaluate", "__driver_evaluate", "domAutomation", "domAutomationController",
      "callPhantom", "_phantom", "__nightmare", "__lastWatirAlert", "_Selenium_IDE_Recorder",
    ];
    const _EXPLICIT_EVAL_RE = /pptr:\\/\\/|devtools:\\/\\/|inspector:\\/\\/|debugger eval code|__puppeteer_evaluation_script__|__playwright_evaluation_script__|UtilityScript\\./i;
    const _LOC_PREFIX_RE = /^(?:[A-Za-z][A-Za-z0-9+.-]*:\\/\\/|(?:about|blob|data|file|javascript):|debugger eval code|\\[native code\\]|<anonymous>|VM\\d+:|eval\\b|$)/i;
    const _BARE_URL_LOC_RE = /^(?:https?|webpack(?:-internal)?):\\/\\/[^\\s]+$/i;
    const _HTTP_URL_PREFIX_RE = /^https?:\\/\\//i;
    const _AT_EVAL_PREFIX_RE = /^at\\s+eval\\s*\\(/i;
    const _EVAL_TAIL_ANON_RE = /(?:<anonymous>(?::\\d+(?::\\d+)?)?|VM\\d+:\\d+(?::\\d+)?)$/i;
    const _ANON_FRAME_RE = /(?:^|,\\s*|\\(\\s*)(?:<anonymous>(?::\\d+|$)|VM\\d+:\\d+|eval\\s+at\\s+<anonymous>)/i;
    const _V8_NATIVE_BUILTIN_FRAME_RE = /^at\\s+(?:new\\s+)?(?!eval\\b)[A-Za-z_$][\\w$.]*\\s*\\(<anonymous>\\)$/;
    const _V8_ASYNC_PROMISE_COMB_RE = /^at\\s+async\\s+Promise\\.(?:all|allSettled|any|race)\\s*\\(index\\s+\\d+\\)$/;
    const _EVAL_FRAME_RE = /^eval\\s+at\\s+(?!<anonymous>)|>\\s*(?:eval|Function)(?::\\d|$)/i;
    const _WEBPACK_DEV_RE = /\\bwebpack(?:-internal)?:\\/\\//i;
    const _BARE_TOP_FRAME_RE = /^(?:at\\s+(?:https?|webpack(?:-internal)?):\\/\\/|@(?:https?|webpack(?:-internal)?):\\/\\/|global code@(?:https?|webpack(?:-internal)?):\\/\\/)/i;
    const _HTTP_URL_TOKEN_RE = /https?:\\/\\/[^\\s]+/gi;
    const _LINE_COL_STRIP_RE = /(?::\\d+(?::\\d+)?)$/i;
    const _SCRIPT_EXT_RE = /\\.(?:m?js|cjs|tsx?|jsx|vue|svelte|astro)$|(?:^|\\/)@(?:vite|id|fs|react-refresh)(?:\\/|$)/i;
    const _EMPTY_SHA256_HEX = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855";

    const _rawConsoleDebug = typeof console !== "undefined" && typeof console.debug === "function" ? console.debug : null;
    const _consoleDebugIsNative = Boolean(_rawConsoleDebug && _rawConsoleDebug.name === "debug" && (() => {
      try { return isNativeNamed(_rawConsoleDebug, "debug"); } catch (_) { return false; }
    })());
    const _consoleDebug = _consoleDebugIsNative ? _reflectApply(_fnBind, _rawConsoleDebug, [console]) : null;
    const _subtle = typeof crypto !== "undefined" && crypto && crypto.subtle ? crypto.subtle : null;
    const _subtleProto = _subtle ? _getProto(_subtle) : null;
    const _SUBTLE_METHODS = ["generateKey", "exportKey", "importKey", "deriveBits", "deriveKey", "verify", "sign", "digest"];
    const _capturedSubtle = Object.create(null);
    if (_subtle) {
      for (let i = 0; i < _SUBTLE_METHODS.length; i++) {
        const m = _SUBTLE_METHODS[i];
        _capturedSubtle[m] = (_subtleProto && typeof _subtleProto[m] === "function") ? _subtleProto[m] : _subtle[m];
      }
    }

    const BASE = ${bpJson};
    const VERSION = ${verJson};
    const SERVER_ECDSA_PUB = ${pubJson};
    const USER_GESTURE_WINDOW_MS = ${ugWin};
    const ALLOW_DEVTOOLS = ${allowDtJson};
    const BLOCK_CDP_ACTIVE = ${blockCdpJson};
    const BLOCK_CONSOLE_EVAL = ${blockCeJson};
    const COLLECT_CE_TELEMETRY = ${collectCeJson};
    const REQUIRE_GUARD_INTEGRITY = ${reqGiJson};
    const FAIL_CLOSED_ON_TAMPER = ${failClosedTamperJson};
    const IS_MONITOR_MODE = ${isMonitorJson};
    const EMBEDDED_VB = ${embeddedVbJson};

    // Fail-closed pre-existing global check: NEVER bail out early via forgeable Function.prototype.toString() comparisons!
    // If a preload script pre-defined window.ProxySnare, mark _initTampered = true AND still wrap fetch/XHR + run embedded VeilBreak.
    let _initTampered = false;
    try {
      if (_getOwnPropDesc(window, "ProxySnare")) {
        _initTampered = true;
      }
    } catch (_) {
      _initTampered = true;
    }

    // Hoisted DataView-free, _Uint8Array/_Int32Array-only FIPS 180-4 SHA-256 kernel (initialized BEFORE embeddedVbBlock to avoid TDZ on synchronous cold-boot probes!)
    const _HEX = "0123456789abcdef";
    const SHA256_K = [
      0x428a2f98,0x71374491,0xb5c0fbcf,0xe9b5dba5,0x3956c25b,0x59f111f1,0x923f82a4,0xab1c5ed5,
      0xd807aa98,0x12835b01,0x243185be,0x550c7dc3,0x72be5d74,0x80deb1fe,0x9bdc06a7,0xc19bf174,
      0xe49b69c1,0xefbe4786,0x0fc19dc6,0x240ca1cc,0x2de92c6f,0x4a7484aa,0x5cb0a9dc,0x76f988da,
      0x983e5152,0xa831c66d,0xb00327c8,0xbf597fc7,0xc6e00bf3,0xd5a79147,0x06ca6351,0x14292967,
      0x27b70a85,0x2e1b2138,0x4d2c6dfc,0x53380d13,0x650a7354,0x766a0abb,0x81c2c92e,0x92722c85,
      0xa2bfe8a1,0xa81a664b,0xc24b8b70,0xc76c51a3,0xd192e819,0xd6990624,0xf40e3585,0x106aa070,
      0x19a4c116,0x1e376c08,0x2748774c,0x34b0bcb5,0x391c0cb3,0x4ed8aa4a,0x5b9cca4f,0x682e6ff3,
      0x748f82ee,0x78a5636f,0x84c87814,0x8cc70208,0x90befffa,0xa4506ceb,0xbef9a3f7,0xc67178f2
    ];
    const SHA256_W = new _Int32Array(64);
    const SHA256_OUT = new _Int32Array(8);
    const POW_SCRATCH = new _Uint8Array(128);
    const _B36_CODES = [
      48,49,50,51,52,53,54,55,56,57,
      97,98,99,100,101,102,103,104,105,106,107,108,109,110,111,112,113,114,115,116,117,118,119,120,121,122
    ];
    const _B36_TMP = new _Uint8Array(12);

    function sha256CompressPadded(buf, padLen) {
      let h0=0x6a09e667,h1=0xbb67ae85,h2=0x3c6ef372,h3=0xa54ff53a,h4=0x510e527f,h5=0x9b05688c,h6=0x1f83d9ab,h7=0x5be0cd19;
      for (let o = 0; o < padLen; o += 64) {
        for (let i = 0; i < 16; i++) {
          const p = o + (i << 2);
          SHA256_W[i] = (buf[p] << 24) | (buf[p + 1] << 16) | (buf[p + 2] << 8) | buf[p + 3];
        }
        for (let i = 16; i < 64; i++) {
          const s0 = ((SHA256_W[i-15]>>>7)|(SHA256_W[i-15]<<25)) ^ ((SHA256_W[i-15]>>>18)|(SHA256_W[i-15]<<14)) ^ (SHA256_W[i-15]>>>3);
          const s1 = ((SHA256_W[i-2]>>>17)|(SHA256_W[i-2]<<15)) ^ ((SHA256_W[i-2]>>>19)|(SHA256_W[i-2]<<13)) ^ (SHA256_W[i-2]>>>10);
          SHA256_W[i] = (SHA256_W[i-16] + s0 + SHA256_W[i-7] + s1) | 0;
        }
        let a=h0,b=h1,c=h2,d=h3,e=h4,f=h5,g=h6,h=h7;
        for (let i = 0; i < 64; i++) {
          const S1 = ((e>>>6)|(e<<26)) ^ ((e>>>11)|(e<<21)) ^ ((e>>>25)|(e<<7));
          const ch = (e & f) ^ (~e & g);
          const t1 = (h + S1 + ch + SHA256_K[i] + SHA256_W[i]) | 0;
          const S0 = ((a>>>2)|(a<<30)) ^ ((a>>>13)|(a<<19)) ^ ((a>>>22)|(a<<10));
          const maj = (a & b) ^ (a & c) ^ (b & c);
          const t2 = (S0 + maj) | 0;
          h=g; g=f; f=e; e=(d+t1)|0; d=c; c=b; b=a; a=(t1+t2)|0;
        }
        h0=(h0+a)|0; h1=(h1+b)|0; h2=(h2+c)|0; h3=(h3+d)|0; h4=(h4+e)|0; h5=(h5+f)|0; h6=(h6+g)|0; h7=(h7+h)|0;
      }
      SHA256_OUT[0] = h0; SHA256_OUT[1] = h1; SHA256_OUT[2] = h2; SHA256_OUT[3] = h3;
      SHA256_OUT[4] = h4; SHA256_OUT[5] = h5; SHA256_OUT[6] = h6; SHA256_OUT[7] = h7;
      return SHA256_OUT;
    }

    function padSha256Into(buf, byteLen) {
      const padLen = ((byteLen + 9 + 63) >> 6) << 6;
      buf[byteLen] = 0x80;
      for (let z = byteLen + 1; z < padLen - 8; z++) buf[z] = 0;
      const bitLen = byteLen * 8;
      const hi = _MathFloor(bitLen / 0x100000000) >>> 0;
      const lo = bitLen >>> 0;
      buf[padLen - 8] = (hi >>> 24) & 255;
      buf[padLen - 7] = (hi >>> 16) & 255;
      buf[padLen - 6] = (hi >>> 8) & 255;
      buf[padLen - 5] = hi & 255;
      buf[padLen - 4] = (lo >>> 24) & 255;
      buf[padLen - 3] = (lo >>> 16) & 255;
      buf[padLen - 2] = (lo >>> 8) & 255;
      buf[padLen - 1] = lo & 255;
      return padLen;
    }

    function sha256WordsFromBytes(bytes, len = bytes.length) {
      const padLen = ((len + 9 + 63) >> 6) << 6;
      const m = new _Uint8Array(padLen);
      for (let i = 0; i < len; i++) m[i] = bytes[i];
      padSha256Into(m, len);
      return sha256CompressPadded(m, padLen);
    }

    function sha256Words(str) {
      const bytes = _encodeUtf8(str);
      return sha256WordsFromBytes(bytes, bytes.length);
    }

    function wordsToHex(w) {
      let out = "";
      for (let i = 0; i < 8; i++) {
        const v = w[i] >>> 0;
        out += _HEX[(v >>> 28) & 15] + _HEX[(v >>> 24) & 15] + _HEX[(v >>> 20) & 15] + _HEX[(v >>> 16) & 15]
             + _HEX[(v >>> 12) & 15] + _HEX[(v >>> 8) & 15] + _HEX[(v >>> 4) & 15] + _HEX[v & 15];
      }
      return out;
    }

    function sha256HexSync(str) {
      return wordsToHex(sha256Words(str));
    }

    // Single-pass in-place UTF-8 whitespace compaction + SHA-256 (eliminates 212k Reflect.apply calls & string allocations!)
    function sha256WsHexSync(str) {
      const raw = _encodeUtf8(str);
      const len = raw.length;
      let outLen = 0;
      let pendingWs = false;
      for (let i = 0; i < len; i++) {
        const b = raw[i];
        if (b === 32 || b === 9 || b === 10 || b === 13 || b === 12 || b === 11) {
          pendingWs = true;
          continue;
        }
        if (b === 0xc2 && i + 1 < len && raw[i + 1] === 0xa0) {
          pendingWs = true;
          i += 1;
          continue;
        }
        if (b === 0xef && i + 2 < len && raw[i + 1] === 0xbb && raw[i + 2] === 0xbf) {
          pendingWs = true;
          i += 2;
          continue;
        }
        if (b === 0xe2 && i + 2 < len && raw[i + 1] === 0x80 && (raw[i + 2] === 0xa8 || raw[i + 2] === 0xa9)) {
          pendingWs = true;
          i += 2;
          continue;
        }
        if (pendingWs && outLen > 0) raw[outLen++] = 32;
        pendingWs = false;
        raw[outLen++] = b;
      }
      return wordsToHex(sha256WordsFromBytes(raw, outLen));
    }

    let _privateVbApi = null;
    let _startupRealmGuardHash = null;
    let _startupRealmTs = -1;
    let _verifiedSourceHash = null;
    let _gestureHandlerRef = null;
    let cachedCdp = { ts: -1, active: false };
    let cdpEverDetected = false;
    let lastFullScanTs = -1;
    const __PS_SHA256_HEX__ = (s) => sha256HexSync(s);
    const __VB_PRIVATE_REGISTER__ = (api) => {
      if (!_privateVbApi && api && typeof api === "object") _privateVbApi = api;
    };
    const __PS_ON_FRESH_REALM__ = (fToStr, fExec, fWin) => {
      try {
        if (_startupRealmGuardHash !== null) return;
        const h = computeGuardHashWithRealm(fToStr, fExec, REQUIRE_GUARD_INTEGRITY, fWin || null, true);
        if (h && h !== "TAMPERED_GUARD" && h !== "TAMPERED_SUBTLE") {
          _startupRealmGuardHash = h;
          _startupRealmTs = monoNow();
        }
      } catch (_) {}
    };
    const __PS_SYNC_CDP__ = (active, ts) => {
      try {
        const t = typeof ts === "number" && Number.isFinite(ts) ? ts : monoNow();
        if (active) cdpEverDetected = true;
        cachedCdp = { ts: t, active: Boolean(active || (!ALLOW_DEVTOOLS && cdpEverDetected)) };
        lastFullScanTs = t;
      } catch (_) {}
    };
    const __PS_MARK_GESTURE__ = (ev) => {
      if (_gestureHandlerRef) _gestureHandlerRef(ev);
    };
    const __PS_OPEN_BASE_REALM__ = () => openBaseFreshRealm();${embeddedVbBlock}
    const _readAttr = (el, name) => {
      if (!el) return null;
      try {
        if (_elGetAttr) return _reflectApply(_elGetAttr, el, [name]);
        return typeof el.getAttribute === "function" ? el.getAttribute(name) : null;
      } catch (_) { return null; }
    };
    const scriptEl = typeof document !== "undefined" ? document.currentScript : null;
    const VB_BRIDGE_TOKEN = _readAttr(scriptEl, "data-vb-bridge") || "";
    const VB_INTERNAL_SYM = _SymbolFor ? _SymbolFor("__VEILBREAK_INTERNAL__") : null;
    const VB_TAMPER_SYM = _SymbolFor ? _SymbolFor("__VB_BRIDGE_TAMPERED__") : null;
    const VB_BRIDGE_SYM = _SymbolFor ? (VB_BRIDGE_TOKEN ? _SymbolFor("__VB_CH_" + VB_BRIDGE_TOKEN) : VB_INTERNAL_SYM) : null;
    function stripUrlQueryHash(raw) {
      const s = _String(raw || "");
      const h = _reflectApply(_strIndexOf, s, ["#"]);
      const noHash = h >= 0 ? _reflectApply(_strSlice, s, [0, h]) : s;
      const q = _reflectApply(_strIndexOf, noHash, ["?"]);
      return q >= 0 ? _reflectApply(_strSlice, noHash, [0, q]) : noHash;
    }
    function splitByChar(raw, sep) {
      const s = _String(raw || "");
      const out = _objCreate(null);
      let n = 0;
      let start = 0;
      const len = s.length;
      while (start <= len) {
        const idx = _reflectApply(_strIndexOf, s, [sep, start]);
        if (idx < 0) {
          out[n++] = _reflectApply(_strSlice, s, [start]);
          break;
        }
        out[n++] = _reflectApply(_strSlice, s, [start, idx]);
        start = idx + 1;
      }
      out.length = n;
      return out;
    }
    const _INITIAL_DOC_RAW = _String((typeof document !== "undefined" && document.location && document.location.href) || (window.location && window.location.href) || "");
    const _initialHashIdx = _reflectApply(_strIndexOf, _INITIAL_DOC_RAW, ["#"]);
    const INITIAL_DOC_FULL_HREF = _INITIAL_DOC_RAW;
    const INITIAL_DOC_HASHLESS_HREF = _initialHashIdx >= 0 ? _reflectApply(_strSlice, _INITIAL_DOC_RAW, [0, _initialHashIdx]) : _INITIAL_DOC_RAW;
    const INITIAL_DOC_URL = stripUrlQueryHash(_INITIAL_DOC_RAW);
    const attrReqVb = _readAttr(scriptEl, "data-require-vb");
    // Monotone policy: data-require-vb="true" may opt in, but untrusted data-require-vb="false" NEVER weakens server-compiled requireVeilBreak:true!
    const REQUIRE_VB = ${reqVbJson} || (attrReqVb !== null && /^(true|1)$/i.test(String(attrReqVb).trim()));
    const RAW_RULES = ${rulesJson};
    const RULES = RAW_RULES.map((r) => {
      if (r && typeof r === "object" && typeof r.regex === "string") {
        try { return new RegExp(r.regex, r.flags || ""); } catch { return null; }
      }
      if (typeof r !== "string") return null;
      const t = r.trim();
      if (t === "*") return "*";
      return normalizeClientPath(t).toLowerCase();
    }).filter(Boolean);

    function isControlEndpointUrl(cleanUrl) {
      if (_reflectApply(_strIndexOf, cleanUrl, [BASE]) < 0) return false;
      try {
        const p = new _URL(cleanUrl).pathname;
        return p === BASE || _reflectApply(_strStartsWith, p, [BASE + "/"]);
      } catch (_) {
        return false;
      }
    }

    function isScriptResourceEntry(entry, cleanUrl, isPreComplete = false) {
      if (entry && typeof entry.responseStatus === "number" && entry.responseStatus >= 400) return false;
      const it = entry && typeof entry.initiatorType === "string" ? entry.initiatorType : "";
      if (it !== "script" && it !== "link" && it !== "other" && it !== "") return false;
      if (isControlEndpointUrl(cleanUrl)) return false;
      if (_reflectApply(_hasOwn, pinnedVerifiedUrls, [cleanUrl])) return true;
      try {
        const u = new _URL(cleanUrl);
        if (!isPreComplete && !_reflectApply(_hasOwn, trustedScriptOrigins, [u.origin])) return false;
        if (it === "script") return true;
        return rxTest(_SCRIPT_EXT_RE, u.pathname);
      } catch (_) {
        return false;
      }
    }

    // Self-contained pure-JS Base64 encoder/decoder (pure arithmetic decode: zero Int16Array/atob tampering surface!)
    const _B64_CHARS = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    function b64Val(c) {
      if (c >= 65 && c <= 90) return c - 65;
      if (c >= 97 && c <= 122) return c - 71;
      if (c >= 48 && c <= 57) return c + 4;
      if (c === 43 || c === 45) return 62;
      if (c === 47 || c === 95) return 63;
      return -1;
    }

    function toBase64(bytes) {
      const u = bytes instanceof _Uint8Array ? bytes : new _Uint8Array(bytes);
      let out = "";
      const len = u.length;
      let i = 0;
      for (; i + 2 < len; i += 3) {
        const n = (u[i] << 16) | (u[i + 1] << 8) | u[i + 2];
        out += _reflectApply(_strCharAt, _B64_CHARS, [(n >>> 18) & 63]) +
               _reflectApply(_strCharAt, _B64_CHARS, [(n >>> 12) & 63]) +
               _reflectApply(_strCharAt, _B64_CHARS, [(n >>> 6) & 63]) +
               _reflectApply(_strCharAt, _B64_CHARS, [n & 63]);
      }
      if (i < len) {
        const rem = len - i;
        const n = (u[i] << 16) | (rem === 2 ? (u[i + 1] << 8) : 0);
        out += _reflectApply(_strCharAt, _B64_CHARS, [(n >>> 18) & 63]) +
               _reflectApply(_strCharAt, _B64_CHARS, [(n >>> 12) & 63]) +
               (rem === 2 ? _reflectApply(_strCharAt, _B64_CHARS, [(n >>> 6) & 63]) : "=") + "=";
      }
      return out;
    }

    function fromBase64(b64) {
      const s = _String(b64 || "");
      const sLen = s.length;
      const vals = new _Uint8Array(sLen);
      let count = 0;
      for (let i = 0; i < sLen; i++) {
        const c = _reflectApply(_strCharCodeAt, s, [i]);
        if (c === 61 || c === 32 || c === 9 || c === 10 || c === 13) continue;
        const v = b64Val(c);
        if (v < 0) throw new _Error("PROXYSNARE_BAD_BASE64");
        vals[count++] = v;
      }
      const rem = count & 3;
      if (rem === 1) throw new _Error("PROXYSNARE_BAD_BASE64");
      const byteLen = ((count >>> 2) * 3) + (rem === 2 ? 1 : rem === 3 ? 2 : 0);
      const out = new _Uint8Array(byteLen);
      let o = 0;
      let i = 0;
      for (; i + 3 < count; i += 4) {
        const n = (vals[i] << 18) | (vals[i + 1] << 12) | (vals[i + 2] << 6) | vals[i + 3];
        out[o++] = (n >>> 16) & 255;
        out[o++] = (n >>> 8) & 255;
        out[o++] = n & 255;
      }
      if (rem === 2) {
        out[o] = ((vals[i] << 2) | (vals[i + 1] >>> 4)) & 255;
      } else if (rem === 3) {
        const n = (vals[i] << 12) | (vals[i + 1] << 6) | vals[i + 2];
        out[o++] = (n >>> 10) & 255;
        out[o] = (n >>> 2) & 255;
      }
      return out;
    }

    function parseBootAttr(el) {
      try {
        const raw = _readAttr(el, "data-ps-boot");
        if (!raw) return null;
        const bytes = fromBase64(raw);
        let text = "";
        if (_textDecoder && _decodeUtf8) {
          text = _reflectApply(_decodeUtf8, _textDecoder, [bytes]);
        } else {
          for (let i = 0; i < bytes.length; i++) text += String.fromCharCode(bytes[i]);
        }
        return _reflectApply(_jsonParse, JSON, [text]);
      } catch (_) {
        return null;
      }
    }

    let pendingBoot = parseBootAttr(scriptEl) || INITIAL_BOOT_ARG;
    let state = null;
    let initPromise = null;
    let sessionGen = 0;
    let seq = 0;
    let clockOffsetMs = 0;
    let reqChain = _NativePromise.resolve();
    let lastTrustedGestureMs = -1;
    let _gateScriptVerified = false;
    let hasInitialInlineScripts = false;
    const VERIFIED_URL_CAP = 2048;
    const pinnedVerifiedUrls = _objCreate(null);
    let pinnedVerifiedCount = 0;
    const verifiedUrlCache = _objCreate(null);
    const verifiedUrlRing = _objCreate(null);
    let verifiedUrlRingCount = 0;
    let verifiedUrlRingIdx = 0;
    const EXACT_SCRIPT_URL_CAP = 512;
    const exactScriptUrls = _objCreate(null);
    const exactScriptUrlRing = _objCreate(null);
    let exactScriptUrlCount = 0;
    let exactScriptUrlIdx = 0;
    const rememberExactScriptUrl = (rawUrl) => {
      if (typeof rawUrl !== "string" || !rawUrl) return;
      const hi = _reflectApply(_strIndexOf, rawUrl, ["#"]);
      const full = hi >= 0 ? _reflectApply(_strSlice, rawUrl, [0, hi]) : rawUrl;
      if (!full || _reflectApply(_hasOwn, exactScriptUrls, [full])) return;
      if (exactScriptUrlCount >= EXACT_SCRIPT_URL_CAP) {
        const ev = exactScriptUrlRing[exactScriptUrlIdx];
        if (ev !== undefined) delete exactScriptUrls[ev];
      } else {
        exactScriptUrlCount += 1;
      }
      exactScriptUrlRing[exactScriptUrlIdx] = full;
      exactScriptUrlIdx = (exactScriptUrlIdx + 1) % EXACT_SCRIPT_URL_CAP;
      exactScriptUrls[full] = 1;
    };
    let rtMissUrlCache = _objCreate(null);
    let rtMissUrlCount = 0;
    let rejectedScriptUrls = _objCreate(null);
    let rejectedScriptUrlCount = 0;
    const rememberRejectedScriptUrl = (u) => {
      if (!u || _reflectApply(_hasOwn, rejectedScriptUrls, [u])) return;
      if (rejectedScriptUrlCount >= 256) {
        rejectedScriptUrls = _objCreate(null);
        rejectedScriptUrlCount = 0;
      }
      rejectedScriptUrls[u] = 1;
      rejectedScriptUrlCount += 1;
    };
    let redirectVerifiedUrlCache = _objCreate(null);
    let redirectVerifiedUrlCount = 0;
    let preCdpRedirectUrlCache = _objCreate(null);
    let preCdpRedirectUrlCount = 0;
    const trustedScriptOrigins = _objCreate(null);
    const taoCrossScriptOrigins = _objCreate(null);
    let hasTaoCrossOriginScript = false;
    let hasRedirectedScriptResource = false;
    let hasSameOriginScriptRedirect = false;
    let hasCrossOriginScriptRedirect = false;
    let domLoadedSeeded = false;
    let lastSeedScriptCount = -1;
    let lastSeedTs = -1;
    if (window.location && window.location.origin) trustedScriptOrigins[window.location.origin] = 1;

    const clearUrlMissCaches = () => {
      if (rtMissUrlCount > 0) { rtMissUrlCache = _objCreate(null); rtMissUrlCount = 0; }
      if (redirectVerifiedUrlCount > 0) { redirectVerifiedUrlCache = _objCreate(null); redirectVerifiedUrlCount = 0; }
    };

    const noteScriptRedirectEntry = (ent, cleanUrl = "", isPreComplete = false, precheckedScript = undefined) => {
      if (!ent) return;
      const it = typeof ent.initiatorType === "string" ? ent.initiatorType : "";
      if (it !== "script" && it !== "link" && it !== "other" && it !== "") return;
      const targetUrl = cleanUrl || stripUrlQueryHash(ent.name);
      if (!targetUrl) return;
      // Enforce origin/pre-complete trust for ALL initiator types including "script" (prevents post-load untrusted <script> from poisoning trustedScriptOrigins/redirect heuristics!)
      const okSc = precheckedScript !== undefined ? precheckedScript : isScriptResourceEntry(ent, targetUrl, isPreComplete);
      if (!okSc) return;
      // 1) Confirmed W3C Resource Timing redirect (same-origin OR TAO-enabled cross-origin)
      if (typeof ent.redirectEnd === "number" && ent.redirectEnd > 0) {
        hasRedirectedScriptResource = true;
        try {
          const u = new _URL(targetUrl);
          const curOrigin = window.location && window.location.origin ? window.location.origin : "";
          const isSameOrig = Boolean(curOrigin && u.origin === curOrigin);
          if (isSameOrig) {
            hasSameOriginScriptRedirect = true;
            if (
              ent.responseStatus === 0 ||
              (ent.transferSize === 0 && (ent.responseStart === 0 || (ent.encodedBodySize === 0 && ent.decodedBodySize === 0)))
            ) {
              hasCrossOriginScriptRedirect = true;
            }
          } else {
            hasCrossOriginScriptRedirect = true;
          }
        } catch (_) {}
        return;
      }
      if (
        ent.transferSize === 0 &&
        typeof ent.responseEnd === "number" && ent.responseEnd > 0
      ) {
        try {
          const u = new _URL(targetUrl);
          const curOrigin = window.location && window.location.origin ? window.location.origin : "";
          const isSameOrig = Boolean(curOrigin && u.origin === curOrigin);
          const isTaoMasked = ent.responseStart === 0 || (ent.encodedBodySize === 0 && ent.decodedBodySize === 0);
          // 2) Same-origin <script> with TAO-masked timing -> proves a same-origin-to-cross-origin 302 redirect occurred
          if (isSameOrig && isTaoMasked) {
            hasRedirectedScriptResource = true;
            hasSameOriginScriptRedirect = true;
            hasCrossOriginScriptRedirect = true;
            return;
          }
          // 3) Cross-origin TAO-masked CDN scripts: record origin in taoCrossScriptOrigins so same-CDN 302 redirects
          //    on trusted CDN origins stay 0-FP WITHOUT globally setting hasRedirectedScriptResource or trusting post-load origins!
          if (!isSameOrig && isTaoMasked) {
            taoCrossScriptOrigins[u.origin] = 1;
            hasTaoCrossOriginScript = true;
            if (isPreComplete) {
              trustedScriptOrigins[u.origin] = 1;
            }
          }
        } catch (_) {}
      }
    };

    const _INLINE_EV_SEL = '[onclick],[onsubmit],[onchange],[oninput],[onblur],[onfocus],[onkeydown],[onkeyup],[onkeypress],[onmousedown],[onmouseup],[onpointerdown],[onpointerup],[ondblclick],[oncontextmenu],[onreset],[onscroll],[ontouchstart],[ontouchend],[onpaste],[oninvalid],[onload],[onerror],[ontoggle],a[href^="javascript:"],a[href^="JAVASCRIPT:"]';
    const isExecInlineScript = (el) => {
      if (!el || _readAttr(el, "src")) return false;
      const rawT = _readAttr(el, "type");
      if (!rawT) return true;
      const sc = _reflectApply(_strIndexOf, rawT, [";"]);
      const mime = _reflectApply(_strTrim, sc >= 0 ? _reflectApply(_strSlice, rawT, [0, sc]) : rawT, []);
      return !mime || rxTest(_EXEC_SCRIPT_TYPE_RE, mime);
    };
    const scanInlineHandlers = () => {
      if (hasInitialInlineScripts || typeof document === "undefined") return;
      try {
        if (document.currentScript && isExecInlineScript(document.currentScript)) {
          hasInitialInlineScripts = true;
        } else if (typeof document.querySelector === "function" && (document.querySelector(_INLINE_EV_SEL) || (() => { try { return Boolean(document.querySelector('a[href^="javascript:" i]')); } catch (_) { return false; } })())) {
          hasInitialInlineScripts = true;
        } else if (typeof document.querySelectorAll === "function") {
          const inlineEls = document.querySelectorAll("script:not([src])");
          for (let i = 0; i < inlineEls.length; i++) {
            if (isExecInlineScript(inlineEls[i])) {
              hasInitialInlineScripts = true;
              break;
            }
          }
        }
      } catch (_) {}
    };
    const seedInitialScriptOrigins = () => {
      try {
        if (typeof document !== "undefined") {
          if (document.readyState === "loading") {
            const sLen = document.scripts ? document.scripts.length : -1;
            const nowS = monoNow();
            if (lastSeedTs >= 0 && sLen >= 0 && sLen === lastSeedScriptCount && nowS >= lastSeedTs && (nowS - lastSeedTs) < 100) {
              return;
            }
            lastSeedScriptCount = sLen;
            lastSeedTs = nowS;
          }
          if (typeof document.querySelectorAll === "function") {
            const initScripts = document.querySelectorAll('script[src], link[rel="modulepreload"][href], link[rel="preload"][as="script"][href]');
            for (let i = 0; i < initScripts.length; i++) {
              const attr = _readAttr(initScripts[i], "src") || _readAttr(initScripts[i], "href");
              if (attr) {
                try {
                  const u = new _URL(attr, baseHref());
                  trustedScriptOrigins[u.origin] = 1;
                  const resolved = stripUrlQueryHash(u.href);
                  if (resolved && !isControlEndpointUrl(resolved)) {
                    rememberVerifiedUrl(resolved, true);
                    rememberExactScriptUrl(u.href);
                  }
                } catch (_) {}
              }
            }
            const preconnectLinks = document.querySelectorAll('link[rel="preconnect"][href], link[rel="dns-prefetch"][href]');
            for (let i = 0; i < preconnectLinks.length; i++) {
              const pHref = _readAttr(preconnectLinks[i], "href");
              if (pHref) {
                try {
                  trustedScriptOrigins[new _URL(pHref, baseHref()).origin] = 1;
                } catch (_) {}
              }
            }
            const importMaps = document.querySelectorAll('script[type="importmap"]');
            if (importMaps && importMaps.length > 0) {
              const seedImportTarget = (val) => {
                if (typeof val !== "string" || !val) return;
                try {
                  const u = new _URL(val, baseHref());
                  trustedScriptOrigins[u.origin] = 1;
                  const resolved = stripUrlQueryHash(u.href);
                  if (resolved && !isControlEndpointUrl(resolved) && !_reflectApply(_strEndsWith, u.pathname, ["/"])) {
                    rememberVerifiedUrl(resolved, true);
                    rememberExactScriptUrl(u.href);
                  }
                } catch (_) {}
              };
              for (let i = 0; i < importMaps.length; i++) {
                try {
                  const rawMap = importMaps[i] && importMaps[i].textContent;
                  if (!rawMap) continue;
                  const parsedMap = _reflectApply(_jsonParse, JSON, [rawMap]);
                  if (parsedMap && typeof parsedMap === "object") {
                    if (parsedMap.imports && typeof parsedMap.imports === "object") {
                      const iKeys = _getOwnPropertyNames(parsedMap.imports);
                      for (let j = 0; j < iKeys.length; j++) seedImportTarget(parsedMap.imports[iKeys[j]]);
                    }
                    if (parsedMap.scopes && typeof parsedMap.scopes === "object") {
                      const sKeys = _getOwnPropertyNames(parsedMap.scopes);
                      for (let j = 0; j < sKeys.length; j++) {
                        const sc = parsedMap.scopes[sKeys[j]];
                        if (sc && typeof sc === "object") {
                          const scKeys = _getOwnPropertyNames(sc);
                          for (let k = 0; k < scKeys.length; k++) seedImportTarget(sc[scKeys[k]]);
                        }
                      }
                    }
                  }
                } catch (_) {}
              }
            }
          }
          if (!hasInitialInlineScripts) {
            scanInlineHandlers();
          }
          if (document.readyState !== "loading") {
            domLoadedSeeded = true;
          }
        }
      } catch (_) {}
    };

    const _needScriptUrlTracking = !ALLOW_DEVTOOLS || BLOCK_CONSOLE_EVAL || COLLECT_CE_TELEMETRY;
    const _needGateResourceTracking = REQUIRE_VB && !EMBEDDED_VB && !VB_BRIDGE_TOKEN;
    let _rtObserver = null;
    let _cachedNavLoadCutoff = -1;
    function getNavLoadCutoffMs() {
      if (_cachedNavLoadCutoff > 0) return _cachedNavLoadCutoff;
      try {
        if (typeof performance !== "undefined" && _perfGetEntriesByType) {
          const navs = _reflectApply(_perfGetEntriesByType, performance, ["navigation"]);
          const nav = navs && navs.length > 0 ? navs[0] : null;
          if (nav) {
            const cutoff = (typeof nav.loadEventEnd === "number" && nav.loadEventEnd > 0)
              ? nav.loadEventEnd
              : ((typeof nav.loadEventStart === "number" && nav.loadEventStart > 0) ? nav.loadEventStart : 0);
            if (cutoff > 0) {
              _cachedNavLoadCutoff = cutoff;
              return cutoff;
            }
          }
        }
      } catch (_) {}
      return 0;
    }
    function isEntryPreComplete(entry, docPreComplete, navCutoff) {
      if (docPreComplete) return true;
      return Boolean(navCutoff > 0 && entry && typeof entry.startTime === "number" && entry.startTime > 0 && entry.startTime <= navCutoff);
    }
    const ingestResourceEntries = (entries, isPreComplete) => {
      if (!entries || !entries.length) return false;
      const curOrigin = window.location && window.location.origin ? window.location.origin : "";
      const navCutoff = isPreComplete ? 0 : getNavLoadCutoffMs();
      let addedNew = false;
      for (let i = 0; i < entries.length; i++) {
        const ent = entries[i];
        if (_needGateResourceTracking && !_gateScriptVerified && isVerifiedGateResourceEntry(ent, curOrigin)) {
          _gateScriptVerified = true;
          if (!_needScriptUrlTracking) {
            try { if (_rtObserver) _rtObserver.disconnect(); } catch (_) {}
            return false;
          }
        }
        if (!_needScriptUrlTracking) continue;
        const it = ent && typeof ent.initiatorType === "string" ? ent.initiatorType : "";
        if (it && it !== "script" && it !== "link" && it !== "other") continue;
        const n = stripUrlQueryHash(ent.name);
        const entPreComplete = isEntryPreComplete(ent, isPreComplete, navCutoff);
        const isSc = Boolean(n) && isScriptResourceEntry(ent, n, entPreComplete);
        noteScriptRedirectEntry(ent, n, entPreComplete, isSc);
        if (isSc) {
          if (!_reflectApply(_hasOwn, pinnedVerifiedUrls, [n]) && !_reflectApply(_hasOwn, verifiedUrlCache, [n])) {
            addedNew = true;
          }
          rememberVerifiedUrl(n, false);
          if (typeof ent.name === "string") rememberExactScriptUrl(ent.name);
          if (entPreComplete && (it === "script" || it === "link")) {
            try { trustedScriptOrigins[new _URL(n).origin] = 1; } catch (_) {}
          }
        } else if (n && it === "script") {
          rememberRejectedScriptUrl(n);
        }
      }
      if (addedNew) clearUrlMissCaches();
      return addedNew;
    };
    // Passive buffered Resource Timing observer gated on active console-eval OR non-embedded VeilBreak gate.js verification
    if (_needScriptUrlTracking || _needGateResourceTracking) {
      try {
        if (typeof PerformanceObserver === "function") {
          const po = new PerformanceObserver((list) => {
            try {
              const entries = list.getEntries();
              const isPreComplete = typeof document === "undefined" || document.readyState !== "complete";
              ingestResourceEntries(entries, isPreComplete);
            } catch (_) {}
          });
          _rtObserver = po;
          po.observe({ type: "resource", buffered: true });
        }
      } catch (_) {}

      if (_needGateResourceTracking) {
        hasVerifiedGateScriptResource();
      }
      if (_needScriptUrlTracking) {
        // Seed load-time CDN script origins & inline-script snapshot now AND once at DOMContentLoaded (when guard.js is injected at top of <head>!)
        seedInitialScriptOrigins();
        if (typeof document !== "undefined" && document.readyState === "loading" && typeof document.addEventListener === "function") {
          document.addEventListener("DOMContentLoaded", seedInitialScriptOrigins, { once: true });
        }
      }
    }

    // Passive trusted user-gesture tracker (monotonic clock immune to Date.now spoofing; excludes DevTools shortcuts & latches CDP!)
    if (typeof window.addEventListener === "function") {
      const isDevToolsKeyShortcut = (ev) => {
        const k = String(ev.key || "");
        const c = String(ev.code || "");
        if (k === "F12" || c === "F12") return true;
        if ((ev.ctrlKey || ev.metaKey) && (ev.shiftKey || (ev.metaKey && ev.altKey))) {
          return (
            k === "I" || k === "i" || k === "J" || k === "j" || k === "C" || k === "c" || k === "K" || k === "k" ||
            c === "KeyI" || c === "KeyJ" || c === "KeyC" || c === "KeyK"
          );
        }
        return false;
      };
      const markGesture = (ev) => {
        if (!ev || ev.isTrusted !== true) return;
        if (ev.type === "keydown" || ev.type === "keyup") {
          if (isDevToolsKeyShortcut(ev)) {
            if (ev.repeat) return;
            if ((!ALLOW_DEVTOOLS || BLOCK_CONSOLE_EVAL) && !cdpEverDetected && ev.type === "keydown" && typeof setTimeout === "function") {
              setTimeout(() => { try { detectCdpActive({ skipCache: true, allowFullScan: false, respectIframeThrottle: true }); } catch (_) {} }, 150);
              setTimeout(() => { try { detectCdpActive({ skipCache: true, allowFullScan: false, respectIframeThrottle: true }); } catch (_) {} }, 600);
            }
            return;
          }
        }
        lastTrustedGestureMs = monoNow();
      };
      _gestureHandlerRef = markGesture;
      // When embedded VeilBreak is active, VeilBreak forwards the 10 overlapping gesture events via __PS_MARK_GESTURE__ (zero duplicate listeners!)
      const psGestureEvents = EMBEDDED_VB
        ? ["mousedown", "drop", "paste", "cut"]
        : ["pointerdown", "pointerup", "mousedown", "touchstart", "keydown", "keyup", "click", "change", "input", "submit", "drop", "paste", "cut", "compositionend"];
      for (const evt of psGestureEvents) {
        window.addEventListener(evt, markGesture, { capture: true, passive: true });
      }
      if ((!ALLOW_DEVTOOLS || BLOCK_CONSOLE_EVAL) && _consoleDebug) {
        let lastUiProbeMs = -1;
        const probeOnUiChange = () => {
          if (cdpEverDetected) return;
          const now = monoNow();
          if (lastUiProbeMs >= 0 && (now - lastUiProbeMs) < 500) return;
          lastUiProbeMs = now;
          try { detectCdpActive({ skipCache: true, allowFullScan: false, respectIframeThrottle: true }); } catch (_) {}
        };
        window.addEventListener("resize", probeOnUiChange, { passive: true });
        window.addEventListener("blur", probeOnUiChange, { passive: true });
        window.addEventListener("focus", probeOnUiChange, { passive: true });
        if (typeof document !== "undefined" && typeof document.addEventListener === "function") {
          document.addEventListener("visibilitychange", probeOnUiChange, { passive: true });
        }
      }
    }

    function enqueueProtected(fn, signal = null) {
      if (signal && signal.aborted) {
        return _NativePromise.reject(signal.reason || new DOMException("The operation was aborted.", "AbortError"));
      }
      const prev = reqChain;
      let cancelWait = null;
      let cancelled = false;
      const waitReady = signal
        ? new _NativePromise((resolve, reject) => {
            const onAbort = () => {
              cancelled = true;
              reject(signal.reason || new DOMException("The operation was aborted.", "AbortError"));
            };
            cancelWait = () => signal.removeEventListener("abort", onAbort);
            signal.addEventListener("abort", onAbort, { once: true });
            _reflectApply(_nativePromiseThen, prev, [() => { cancelWait(); resolve(); }, () => { cancelWait(); resolve(); }]);
          })
        : prev;
      const run = _reflectApply(_nativePromiseThen, waitReady, [() => {
        if (cancelled || (signal && signal.aborted)) {
          throw (signal && signal.reason) || new DOMException("The operation was aborted.", "AbortError");
        }
        return fn();
      }]);
      const settle = () => _reflectApply(_nativePromiseThen, run, [() => {}, () => {}]);
      reqChain = _reflectApply(_nativePromiseThen, prev, [settle, settle]);
      return run;
    }

    function toHex(buf) {
      const u = buf instanceof _Uint8Array ? buf : new _Uint8Array(buf);
      let out = "";
      for (let i = 0; i < u.length; i++) {
        const b = u[i];
        out += _HEX[b >>> 4] + _HEX[b & 15];
      }
      return out;
    }

    function isZoneJsNativeThenPatch(thenDesc) {
      if (!thenDesc || typeof thenDesc.value !== "function") return false;
      const zOrig = _getOwnPropDesc(_NativePromise.prototype, "__zone_symbol__then");
      if (!zOrig || zOrig.value !== _nativePromiseThen) return false;
      const Z = typeof window !== "undefined" ? window.Zone : undefined;
      return Boolean(Z && (typeof Z === "function" || typeof Z === "object") && Z.current && typeof Z.current === "object");
    }

    function isZoneJsPromiseCtor() {
      if (typeof window === "undefined") return false;
      const Z = window.Zone;
      if (!Z || (typeof Z !== "function" && typeof Z !== "object") || !Z.current || typeof Z.current !== "object") return false;
      const pDesc = _getOwnPropDesc(window, "Promise");
      const liveP = pDesc && !pDesc.get && !pDesc.set ? pDesc.value : null;
      if (typeof liveP !== "function") return false;
      // Accept both unminified ZoneAwarePromise AND production Angular ng-build minified class (which keeps static toString())
      const isZoneCtorName =
        liveP.name === "ZoneAwarePromise" ||
        (_reflectApply(_hasOwn, liveP, ["toString"]) &&
          typeof liveP.toString === "function" &&
          liveP.toString() === "function ZoneAwarePromise() { [native code] }");
      if (!isZoneCtorName) return false;
      const origDesc = _getOwnPropDesc(window, "__zone_symbol__Promise");
      return Boolean(origDesc && !origDesc.get && !origDesc.set && origDesc.value === _NativePromise);
    }

    function isPromiseIntegrityOk() {
      try {
        // Defeat mutable global constructor decoys (window.Object/Array/RegExp/Symbol/ArrayBuffer/CryptoKey/Response = decoy)
        if (
          Object !== _Object ||
          Array !== _Array ||
          RegExp !== _RegExp ||
          Function !== _Function ||
          Reflect !== _Reflect ||
          Date !== _Date ||
          Math !== _Math ||
          JSON !== _JSON ||
          String !== _String ||
          Uint8Array !== _Uint8Array ||
          Int32Array !== _Int32Array ||
          _Object.prototype !== _objProto ||
          _Array.prototype !== _arrProto ||
          _RegExp.prototype !== _regExpProto ||
          _Function.prototype !== _fnProto ||
          (_Symbol && (typeof Symbol !== "function" || Symbol !== _Symbol)) ||
          (_ArrayBuffer && (typeof ArrayBuffer !== "function" || ArrayBuffer !== _ArrayBuffer || ArrayBuffer.prototype !== _arrayBufferProto)) ||
          (_CryptoKey && (typeof CryptoKey !== "function" || CryptoKey !== _CryptoKey || CryptoKey.prototype !== _cryptoKeyProto)) ||
          (_Response && (typeof Response !== "function" || Response !== _Response || Response.prototype !== _RespProto)) ||
          (typeof URL !== "function" || URL !== _URL || URL.prototype !== _urlProto) ||
          (_urlOriginGet && _getOwnPropDesc(_urlProto, "origin")?.get !== _urlOriginGet) ||
          (_urlPathnameGet && _getOwnPropDesc(_urlProto, "pathname")?.get !== _urlPathnameGet)
        ) {
          return false;
        }
        const winPDesc = typeof window !== "undefined" ? _getOwnPropDesc(window, "Promise") : null;
        const livePromiseOk =
          Promise === _NativePromise &&
          (!winPDesc || (!winPDesc.get && !winPDesc.set && winPDesc.value === _NativePromise));
        if (!livePromiseOk && !isZoneJsPromiseCtor()) return false;
        const ctorDesc = _getOwnPropDesc(_NativePromise.prototype, "constructor");
        const thenDesc = _getOwnPropDesc(_NativePromise.prototype, "then");
        if (!ctorDesc || ctorDesc.value !== _NativePromise) return false;
        // Allow Angular Zone.js's legitimate native-then bridge (all SubtleCrypto calls already execute strictly via captured _nativePromiseThen + null-prototype boxing!)
        if (!thenDesc || (thenDesc.value !== _nativePromiseThen && !isZoneJsNativeThenPatch(thenDesc))) return false;
        const reExecDesc = _getOwnPropDesc(_regExpProto, "exec");
        if (!reExecDesc || reExecDesc.value !== _regexExec) return false;
        if (_symSpecies) {
          if (_Symbol.species !== _symSpecies) return false;
          const spDesc = _getOwnPropDesc(_NativePromise, _symSpecies);
          if (_promiseSpeciesGet) {
            if (!spDesc || spDesc.get !== _promiseSpeciesGet) return false;
          } else if (spDesc || (_symSpecies in _NativePromise)) {
            return false;
          }
        }
        if (_arrayIter && _symIterator) {
          if (_Symbol.iterator !== _symIterator) return false;
          const aiDesc = _getOwnPropDesc(_arrProto, _symIterator);
          if (!aiDesc || aiDesc.get || aiDesc.set || aiDesc.value !== _arrayIter) return false;
        }
        if (_arrayValues) {
          const avDesc = _getOwnPropDesc(_arrProto, "values");
          if (!avDesc || avDesc.get || avDesc.set || avDesc.value !== _arrayValues) return false;
        }
        if (_arrIterProto && _arrIterNext) {
          const nextDesc = _getOwnPropDesc(_arrIterProto, "next");
          if (!nextDesc || nextDesc.get || nextDesc.set || nextDesc.value !== _arrIterNext) return false;
        }
        if (_Object.create !== _objCreate) return false;
        if (_symSplit && (_Symbol.split !== _symSplit || (_symSplit in _strProto))) return false;
        if (_symReplace && (_Symbol.replace !== _symReplace || (_symReplace in _strProto))) return false;
        if (_symMatch && (_Symbol.match !== _symMatch || (_symMatch in _strProto))) return false;
        if ("then" in _objProto) return false;
        if (("get" in _objProto) || ("set" in _objProto) || ("value" in _objProto) || ("writable" in _objProto)) return false;
        if (_arrayBufferProto && ("then" in _arrayBufferProto)) return false;
        if (_cryptoKeyProto && ("then" in _cryptoKeyProto)) return false;
        if (_RespProto && ("then" in _RespProto)) return false;
        if (hasProtoIndexPollutionFast()) return false;
        return true;
      } catch (_) {
        return false;
      }
    }

    function assertPromiseIntegrity() {
      if (!isPromiseIntegrityOk()) throw new _Error("PROXYSNARE_PROMISE_TAMPERED");
    }

    // Boxes resolved values inside a null-prototype object after re-checking Promise/iterator integrity on settlement
    // so ECMA-262 Promise Resolve Functions NEVER read .then on CryptoKey/ArrayBuffer/Object (defeats Symbol.species & iterator TOCTOU!).
    function unwrapNativePromise(p) {
      assertPromiseIntegrity();
      if (!p || (typeof p !== "object" && typeof p !== "function") || _reflectApply(_hasOwn, p, ["constructor"]) || _reflectApply(_hasOwn, p, ["then"])) {
        throw new _Error("PROXYSNARE_PROMISE_TAMPERED");
      }
      return new _NativePromise((resolve, reject) => {
        _reflectApply(_nativePromiseThen, p, [
          (val) => {
            try {
              assertPromiseIntegrity();
              const box = _objCreate(null);
              box.v = val;
              resolve(box);
            } catch (e) {
              reject(e);
            }
          },
          reject,
        ]);
      });
    }

    function solvePow(challenge, difficulty) {
      if (!difficulty || difficulty <= 0 || !challenge) return "0";
      const prefix = "PS_POW_V2|" + challenge + "|";
      const prefixBytes = _encodeUtf8(prefix);
      const useScratch = difficulty <= 32 && prefixBytes.length <= 96;
      if (useScratch) {
        POW_SCRATCH.set(prefixBytes, 0);
        const pLen = prefixBytes.length;
        for (let i = 0; i < 5_000_000; i++) {
          let n = i;
          let nLen = 0;
          if (n === 0) {
            POW_SCRATCH[pLen] = 48;
            nLen = 1;
          } else {
            while (n > 0) {
              const q = (n / 36) | 0;
              _B36_TMP[nLen++] = _B36_CODES[n - q * 36];
              n = q;
            }
            for (let j = 0; j < nLen; j++) POW_SCRATCH[pLen + j] = _B36_TMP[nLen - 1 - j];
          }
          const padLen = padSha256Into(POW_SCRATCH, pLen + nLen);
          const h0 = sha256CompressPadded(POW_SCRATCH, padLen)[0] >>> 0;
          if (_MathClz32(h0) >= difficulty) return i.toString(36);
        }
      } else {
        for (let i = 0; i < 5_000_000; i++) {
          const nonce = i.toString(36);
          const words = sha256Words(prefix + nonce);
          let rem = difficulty;
          let ok = true;
          for (let k = 0; k < words.length && rem > 0; k++) {
            const w = words[k] >>> 0;
            if (rem >= 32) { if (w !== 0) { ok = false; break; } rem -= 32; }
            else { ok = _MathClz32(w) >= rem; break; }
          }
          if (ok) return nonce;
        }
      }
      throw new _Error("PROXYSNARE_POW_TIMEOUT");
    }

    function hasSameOriginGateScriptEl(origin) {
      try {
        if (!origin || typeof document === "undefined" || typeof document.querySelectorAll !== "function") return false;
        const els = document.querySelectorAll("script[src]");
        const base = baseHref();
        for (let i = 0; i < els.length; i++) {
          const rawSrc = _readAttr(els[i], "src");
          if (!rawSrc) continue;
          try {
            const cu = stripUrlQueryHash(new _URL(rawSrc, base).href);
            if (_reflectApply(_strStartsWith, cu, [origin + "/"]) && _reflectApply(_strEndsWith, cu, ["/gate.js"])) return true;
          } catch (_) {}
        }
      } catch (_) {}
      return false;
    }

    function isVerifiedGateResourceEntry(ent, origin) {
      if (!ent || typeof ent.name !== "string") return false;
      const it = typeof ent.initiatorType === "string" ? ent.initiatorType : "";
      if (it && it !== "script" && it !== "link" && it !== "other") return false;
      const clean = stripUrlQueryHash(ent.name);
      if (!_reflectApply(_strEndsWith, clean, ["/gate.js"])) return false;
      const sameOrig = Boolean(origin && _reflectApply(_strStartsWith, clean, [origin + "/"]));
      if (!sameOrig) return false;
      if (it === "link" && !hasSameOriginGateScriptEl(origin)) return false;
      const statusOk = typeof ent.responseStatus === "number" ? ((ent.responseStatus >= 200 && ent.responseStatus < 300) || ent.responseStatus === 304) : true;
      if (!statusOk) return false;
      return (
        typeof ent.decodedBodySize !== "number" ||
        ent.decodedBodySize > 0 ||
        ent.transferSize > 0 ||
        ent.encodedBodySize > 0 ||
        ent.responseStatus === 200 ||
        ent.responseStatus === 304 ||
        (typeof ent.responseStatus !== "number" && typeof ent.responseEnd === "number" && ent.responseEnd > 0 && typeof ent.duration === "number" && ent.duration >= 0)
      );
    }

    function hasVerifiedGateScriptResource() {
      if (_gateScriptVerified) return true;
      try {
        if (typeof performance === "undefined" || !_perfGetEntriesByType) return false;
        const entries = _reflectApply(_perfGetEntriesByType, performance, ["resource"]) || [];
        const origin = window.location && window.location.origin ? window.location.origin : "";
        for (let i = 0; i < entries.length; i++) {
          if (isVerifiedGateResourceEntry(entries[i], origin)) {
            _gateScriptVerified = true;
            return true;
          }
        }
        return false;
      } catch (_) {
        return false;
      }
    }

    function getTrustedVeilBreak() {
      if (EMBEDDED_VB) return _privateVbApi;
      // Fail closed if VB_TAMPER_SYM is present on window with ANY value (prevents pre-defining { value: false, configurable: false }!)
      if (VB_TAMPER_SYM && (_reflectApply(_hasOwn, window, [VB_TAMPER_SYM]) || window[VB_TAMPER_SYM] !== undefined)) return null;
      const sym = VB_BRIDGE_TOKEN ? VB_BRIDGE_SYM : VB_INTERNAL_SYM;
      if (!sym) return null;
      try {
        const desc = _getOwnPropDesc(window, sym);
        if (!desc || desc.configurable !== false || desc.writable !== false || !desc.value || !_isFrozen(desc.value)) return null;
        // Without a server-stamped per-HTML data-vb-bridge token, require Resource Timing proof that gate.js actually loaded
        // (defeats Playwright page.route("**/gate.js*", r => r.abort()) + addInitScript(Symbol.for("__VEILBREAK_INTERNAL__"))!)
        if (!VB_BRIDGE_TOKEN && REQUIRE_VB) {
          const pubDesc = _getOwnPropDesc(window, "VeilBreak");
          if (!pubDesc || pubDesc.configurable !== false || pubDesc.writable !== false || pubDesc.value !== desc.value) return null;
          if (!hasVerifiedGateScriptResource()) return null;
        }
        return desc.value;
      } catch (_) {
        return null;
      }
    }

    function rememberVerifiedUrl(u, pinned = false) {
      if (pinned) {
        if (!_reflectApply(_hasOwn, pinnedVerifiedUrls, [u]) && pinnedVerifiedCount < VERIFIED_URL_CAP) {
          pinnedVerifiedUrls[u] = 1;
          pinnedVerifiedCount += 1;
        }
        return true;
      }
      if (_reflectApply(_hasOwn, pinnedVerifiedUrls, [u]) || _reflectApply(_hasOwn, verifiedUrlCache, [u])) return true;
      if (verifiedUrlRingCount >= VERIFIED_URL_CAP) {
        const evicted = verifiedUrlRing[verifiedUrlRingIdx];
        if (evicted !== undefined) delete verifiedUrlCache[evicted];
      } else {
        verifiedUrlRingCount += 1;
      }
      verifiedUrlRing[verifiedUrlRingIdx] = u;
      verifiedUrlRingIdx = (verifiedUrlRingIdx + 1) % VERIFIED_URL_CAP;
      verifiedUrlCache[u] = 1;
      return true;
    }

    function rememberRtMiss(u) {
      if (_reflectApply(_hasOwn, rtMissUrlCache, [u])) return;
      if (rtMissUrlCount >= 256) {
        rtMissUrlCache = _objCreate(null);
        rtMissUrlCount = 0;
      }
      rtMissUrlCache[u] = 1;
      rtMissUrlCount += 1;
    }

    function rememberRedirectVerified(u) {
      if (!cdpEverDetected && !_reflectApply(_hasOwn, preCdpRedirectUrlCache, [u])) {
        if (preCdpRedirectUrlCount >= 256) {
          preCdpRedirectUrlCache = _objCreate(null);
          preCdpRedirectUrlCount = 0;
        }
        preCdpRedirectUrlCache[u] = 1;
        preCdpRedirectUrlCount += 1;
      }
      if (_reflectApply(_hasOwn, redirectVerifiedUrlCache, [u])) return true;
      if (redirectVerifiedUrlCount >= 256) {
        redirectVerifiedUrlCache = _objCreate(null);
        redirectVerifiedUrlCount = 0;
      }
      redirectVerifiedUrlCache[u] = 1;
      redirectVerifiedUrlCount += 1;
      return true;
    }

    function isKnownPageScriptUrl(urlCandidate, allowTrustedOriginRedirect = false, allowConfirmedRedirectOnly = false, crossOriginPolicy = 0, preStrippedClean = "", allowSameOriginRedirV8 = false) {
      try {
        const clean = preStrippedClean || stripUrlQueryHash(urlCandidate);
        if (!clean) return false;
        // O(1) verified-URL caches already exclude control endpoints on insertion -> skip isControlEndpointUrl / new URL() on hot cache hits!
        if (_reflectApply(_hasOwn, pinnedVerifiedUrls, [clean])) return true;
        if (_reflectApply(_hasOwn, verifiedUrlCache, [clean])) return true;
        if (_reflectApply(_hasOwn, preCdpRedirectUrlCache, [clean])) return true;
        const allowHeuristicNow = allowTrustedOriginRedirect || (allowConfirmedRedirectOnly && (hasRedirectedScriptResource || hasTaoCrossOriginScript));
        if (allowHeuristicNow && _reflectApply(_hasOwn, redirectVerifiedUrlCache, [clean])) return true;
        if (isControlEndpointUrl(clean)) return false;
        // Only match immutable INITIAL_DOC_URL when initial DOM actually had inline executable scripts/handlers (lazy re-scan while loading if throttled)!
        if (INITIAL_DOC_URL && clean === INITIAL_DOC_URL) {
          if (!domLoadedSeeded && !hasInitialInlineScripts) scanInlineHandlers();
          return (!domLoadedSeeded || hasInitialInlineScripts) ? rememberVerifiedUrl(clean, true) : false;
        }
        // Drain pending buffered PerformanceObserver records synchronously so lazy dynamic import() chunks past the 250-entry RT buffer cap are seen immediately!
        const isPreCompleteNow = typeof document === "undefined" || document.readyState !== "complete";
        if (_rtObserver && typeof _rtObserver.takeRecords === "function") {
          try {
            const pending = _rtObserver.takeRecords();
            if (pending && pending.length) {
              ingestResourceEntries(pending, isPreCompleteNow);
              if (_reflectApply(_hasOwn, pinnedVerifiedUrls, [clean]) || _reflectApply(_hasOwn, verifiedUrlCache, [clean])) {
                return true;
              }
            }
          } catch (_) {}
        }
        const knownRtMiss = _reflectApply(_hasOwn, rtMissUrlCache, [clean]);
        if (knownRtMiss && !allowTrustedOriginRedirect && !allowConfirmedRedirectOnly) return false;
        if (!knownRtMiss && typeof performance !== "undefined" && _perfGetEntriesByType) {
          const entries = _reflectApply(_perfGetEntriesByType, performance, ["resource"]) || [];
          const navCutoff = isPreCompleteNow ? 0 : getNavLoadCutoffMs();
          for (let i = 0; i < entries.length; i++) {
            const ent = entries[i];
            const n = stripUrlQueryHash(ent && ent.name);
            const entPreComplete = isEntryPreComplete(ent, isPreCompleteNow, navCutoff);
            const isSc = Boolean(n) && isScriptResourceEntry(ent, n, entPreComplete);
            noteScriptRedirectEntry(ent, n, entPreComplete, isSc);
            if (isSc && typeof ent.name === "string") rememberExactScriptUrl(ent.name);
            else if (n && !isSc && ent && ent.initiatorType === "script") rememberRejectedScriptUrl(n);
            if (n === clean && isSc) return rememberVerifiedUrl(clean, false);
          }
          // Record RT miss so subsequent closed-DevTools fetches stay O(1) without rescanning Resource Timing!
          rememberRtMiss(clean);
        }
        // Never accept a post-load dynamically injected untrusted <script> entry via redirect heuristics!
        if (_reflectApply(_hasOwn, rejectedScriptUrls, [clean])) return false;
        // Strictly enforce trustedScriptOrigins on redirects whenever DevTools/CDP is open; only allow cross-origin
        // destinations on proven redirect evidence (policy 2: DevTools closed + any redirect; policy 1: !strictCdpMode + TAO-masked cross-origin 302, or V8 unspoofable CallSite + same-origin 302)!
        if (allowTrustedOriginRedirect || allowConfirmedRedirectOnly) {
          const parsed = new _URL(clean);
          if (rxTest(_SCRIPT_EXT_RE, parsed.pathname)) {
            const originTrusted = _reflectApply(_hasOwn, trustedScriptOrigins, [parsed.origin]);
            const originTaoRedirectable = originTrusted && _reflectApply(_hasOwn, taoCrossScriptOrigins, [parsed.origin]);
            // Under BLOCK_CONSOLE_EVAL, never accept unverified fabricated .js URLs on trusted origins without actual redirect evidence (closes Firefox/Safari //# sourceURL= spoofing)!
            const trustedAllowed =
              originTrusted &&
              (hasRedirectedScriptResource || originTaoRedirectable || (!BLOCK_CONSOLE_EVAL && allowTrustedOriginRedirect));
            const crossOrigAllowed =
              (crossOriginPolicy === 2 && (hasCrossOriginScriptRedirect || hasRedirectedScriptResource)) ||
              (crossOriginPolicy === 1 && (hasCrossOriginScriptRedirect || (allowSameOriginRedirV8 && hasSameOriginScriptRedirect)));
            if (trustedAllowed || crossOrigAllowed) {
              return rememberRedirectVerified(clean);
            }
          }
        }
      } catch (_) {}
      return false;
    }

    function extractTrailingParen(s) {
      if (!s || _reflectApply(_strCharCodeAt, s, [s.length - 1]) !== 41) return "";
      let depth = 0;
      for (let i = s.length - 1; i >= 0; i--) {
        const c = _reflectApply(_strCharCodeAt, s, [i]);
        if (c === 41) depth++;
        else if (c === 40) {
          depth--;
          if (depth === 0) return _reflectApply(_strSlice, s, [i + 1, s.length - 1]);
        }
      }
      return "";
    }

    let rtExactSyncedCount = -1;
    function syncExactScriptUrlsFromRt() {
      const isPreCompleteNow = typeof document === "undefined" || document.readyState !== "complete";
      if (_rtObserver && typeof _rtObserver.takeRecords === "function") {
        try {
          const pending = _rtObserver.takeRecords();
          if (pending && pending.length) ingestResourceEntries(pending, isPreCompleteNow);
        } catch (_) {}
      }
      if (typeof performance !== "undefined" && _perfGetEntriesByType) {
        try {
          const entries = _reflectApply(_perfGetEntriesByType, performance, ["resource"]) || [];
          if (entries.length !== rtExactSyncedCount) {
            rtExactSyncedCount = entries.length;
            const navCutoff = isPreCompleteNow ? 0 : getNavLoadCutoffMs();
            for (let i = 0; i < entries.length; i++) {
              const ent = entries[i];
              const n = stripUrlQueryHash(ent && ent.name);
              const entPreComplete = isEntryPreComplete(ent, isPreCompleteNow, navCutoff);
              const isSc = Boolean(n) && isScriptResourceEntry(ent, n, entPreComplete);
              noteScriptRedirectEntry(ent, n, entPreComplete, isSc);
              if (isSc && typeof ent.name === "string") {
                rememberVerifiedUrl(n, false);
                rememberExactScriptUrl(ent.name);
              }
            }
          }
        } catch (_) {}
      }
    }

    function isExactKnownUrl(rawLoc) {
      const spLine = _reflectApply(_strIndexOf, rawLoc, [" line "]);
      const cand = spLine >= 0 ? _reflectApply(_strSlice, rawLoc, [0, spLine]) : rawLoc;
      const bareNoPos = _regexSymReplace
        ? _reflectApply(_regexSymReplace, _LINE_COL_STRIP_RE, [cand, ""])
        : _reflectApply(_strReplace, cand, [_LINE_COL_STRIP_RE, ""]);
      const curHref = _String((typeof document !== "undefined" && document.location && document.location.href) || (window.location && window.location.href) || "");
      const checkMatch = () => {
        if (
          bareNoPos === INITIAL_DOC_FULL_HREF ||
          (curHref && bareNoPos === curHref) ||
          bareNoPos === INITIAL_DOC_HASHLESS_HREF ||
          _reflectApply(_hasOwn, exactScriptUrls, [bareNoPos])
        ) {
          return true;
        }
        const bHi = _reflectApply(_strIndexOf, bareNoPos, ["#"]);
        if (bHi >= 0) {
          const bareNoHash = _reflectApply(_strSlice, bareNoPos, [0, bHi]);
          const frag = _reflectApply(_strSlice, bareNoPos, [bHi + 1]);
          if (
            _reflectApply(_strIndexOf, frag, ["@"]) < 0 &&
            (bareNoHash === INITIAL_DOC_HASHLESS_HREF || _reflectApply(_hasOwn, exactScriptUrls, [bareNoHash]))
          ) {
            return true;
          }
        }
        return false;
      };
      if (checkMatch()) return true;
      syncExactScriptUrlsFromRt();
      return checkMatch();
    }

    function isRedirectedAtScriptUrl(cand, relAt) {
      if (!(hasRedirectedScriptResource || hasTaoCrossOriginScript)) syncExactScriptUrlsFromRt();
      if (!(hasRedirectedScriptResource || hasTaoCrossOriginScript)) return false;
      const spLine = _reflectApply(_strIndexOf, cand, [" line "]);
      const urlHead = spLine >= 0 ? _reflectApply(_strSlice, cand, [0, spLine]) : cand;
      if (relAt >= urlHead.length) return false;
      const beforeAt = _reflectApply(_strSlice, urlHead, [0, relAt]);
      if (rxTest(_WS_RE, beforeAt) || _reflectApply(_strIndexOf, beforeAt, ["?"]) >= 0 || _reflectApply(_strIndexOf, beforeAt, ["#"]) >= 0) return false;
      const afterAt = _reflectApply(_strSlice, urlHead, [relAt + 1]);
      if (_reflectApply(_strIndexOf, afterAt, ["/"]) < 0) return false;
      const bareNoPos = _regexSymReplace
        ? _reflectApply(_regexSymReplace, _LINE_COL_STRIP_RE, [urlHead, ""])
        : _reflectApply(_strReplace, urlHead, [_LINE_COL_STRIP_RE, ""]);
      const cleanBare = stripUrlQueryHash(bareNoPos);
      if (!rxTest(_SCRIPT_EXT_RE, cleanBare)) return false;
      if (hasRedirectedScriptResource) return true;
      try {
        return Boolean(_reflectApply(_hasOwn, taoCrossScriptOrigins, [new _URL(cleanBare).origin]));
      } catch (_) {
        return false;
      }
    }

    // Structurally extracts ONLY the trailing source location of a V8/Gecko/WebKit stack frame (never attacker-controlled function name!)
    function extractFrameLocation(ln) {
      if (!ln) return "";
      if (_hasV8ErrorHeader && _reflectApply(_strStartsWith, ln, ["at "])) {
        const tail = extractTrailingParen(ln);
        if (tail) return tail;
        let rest = _reflectApply(_strTrim, _reflectApply(_strSlice, ln, [3]), []);
        if (_reflectApply(_strStartsWith, rest, ["async "])) {
          rest = _reflectApply(_strTrim, _reflectApply(_strSlice, rest, [6]), []);
        }
        return rest;
      }
      // SpiderMonkey / JavaScriptCore: <fnName>@<location> — scan backward for last @ followed by a valid location prefix.
      // Any split before lastAt (URL containing '@') MUST match an exact known document/script URL or proven redirected versioned CDN script (defeats "a@https://site/@x.js:1:1"!).
      let pos = ln.length;
      let lastAt = -1;
      while (pos > 0) {
        const idx = _reflectApply(_strLastIndexOf, ln, ["@", pos - 1]);
        if (idx < 0) break;
        if (lastAt < 0) lastAt = idx;
        const after = _reflectApply(_strSlice, ln, [idx + 1]);
        if (rxTest(_LOC_PREFIX_RE, after)) {
          if (idx === lastAt) return after;
          const relLastAt = lastAt - idx - 1;
          const beforeLastAt = _reflectApply(_strSlice, after, [0, relLastAt]);
          if (!rxTest(_WS_RE, beforeLastAt) && (isExactKnownUrl(after) || isRedirectedAtScriptUrl(after, relLastAt))) return after;
        }
        pos = idx;
      }
      // Preserve Safari/JSC bare-URL anonymous frames containing '@' ONLY when the full URL matches an exact known document/script URL
      // or a proven redirected versioned CDN script (0-FP on /@vite/client, alpinejs@3.14.1/dist/cdn.min.js, ?email=a@b.com; blocks "https://site/@x.js:1:1"!).
      if (lastAt >= 0 && rxTest(_BARE_URL_LOC_RE, ln)) {
        if (isExactKnownUrl(ln) || isRedirectedAtScriptUrl(ln, lastAt)) return ln;
      }
      return lastAt >= 0 ? _reflectApply(_strSlice, ln, [lastAt + 1]) : ln;
    }

    // Recursively unwraps V8 eval-at parent location chains in strictly O(L) linear time (zero ReDoS backtracking!)
    function unwrapEvalOrigin(loc) {
      let cur = loc;
      for (let step = 0; step < 16; step++) {
        if (!_reflectApply(_strStartsWith, cur, ["eval at "])) break;
        let noTail = _reflectApply(_strTrim, cur, []);
        const mTail = _reflectApply(_regexExec, _EVAL_TAIL_ANON_RE, [noTail]);
        if (mTail) {
          const prevCh = mTail.index > 0 ? _reflectApply(_strCharCodeAt, noTail, [mTail.index - 1]) : 44;
          if (mTail.index === 0 || prevCh <= 32 || prevCh === 44) {
            noTail = _reflectApply(_strTrim, _reflectApply(_strSlice, noTail, [0, mTail.index]), []);
            if (noTail.length > 0 && _reflectApply(_strCharCodeAt, noTail, [noTail.length - 1]) === 44) {
              noTail = _reflectApply(_strTrim, _reflectApply(_strSlice, noTail, [0, -1]), []);
            }
          }
        }
        const inner = extractTrailingParen(noTail);
        if (!inner) return _reflectApply(_strTrim, _reflectApply(_strSlice, noTail, [8]), []);
        cur = inner;
      }
      return cur;
    }

    // Extracts all http(s) URLs from a stack frame location in strictly O(L) time without truncating interior ')' in /(auth)/page.js or interior ',' in CDN combo URLs
    function extractFrameUrls(loc) {
      const urls = _objCreate(null);
      let n = 0;
      _HTTP_URL_TOKEN_RE.lastIndex = 0;
      let m;
      while ((m = _reflectApply(_regexExec, _HTTP_URL_TOKEN_RE, [loc])) !== null) {
        let tok = m[0];
        if (tok.length > 0 && _reflectApply(_strCharCodeAt, tok, [tok.length - 1]) === 44) {
          tok = _reflectApply(_strSlice, tok, [0, -1]);
        }
        if (tok.length > 0 && _reflectApply(_strCharCodeAt, tok, [tok.length - 1]) === 41) {
          let open = 0, close = 0;
          for (let j = 0; j < tok.length; j++) {
            const ch = _reflectApply(_strCharCodeAt, tok, [j]);
            if (ch === 40) open++;
            else if (ch === 41) close++;
          }
          while (tok.length > 0 && _reflectApply(_strCharCodeAt, tok, [tok.length - 1]) === 41) {
            if (close > open || rxTest(_LINE_COL_PAREN_RE, tok)) {
              tok = _reflectApply(_strSlice, tok, [0, -1]);
              close--;
            } else {
              break;
            }
          }
        }
        const stripped = _regexSymReplace
          ? _reflectApply(_regexSymReplace, _LINE_COL_STRIP_RE, [tok, ""])
          : _reflectApply(_strReplace, tok, [_LINE_COL_STRIP_RE, ""]);
        if (stripped) urls[n++] = stripped;
      }
      urls.length = n;
      return urls;
    }

    // Minimal 6-intrinsic fresh iframe helper isolated inside a closed ShadowRoot (defeats synchronous Chromium/WebKit
    // about:blank capture-phase 'load' listeners because load has composed:false, and avoids unverified frame.style access!)
    function openBaseFreshRealm() {
      let host = null;
      let frame = null;
      const cleanup = () => {
        if (host) {
          try { if (_elRemove) _reflectApply(_elRemove, host, []); else host.remove(); } catch (_) {}
          host = null;
        }
        if (frame) {
          try { if (_elRemove) _reflectApply(_elRemove, frame, []); else frame.remove(); } catch (_) {}
          frame = null;
        }
      };
      try {
        if (!isPromiseIntegrityOk()) {
          return { ok: false, frame: null, host: null, win: null, fToStr: null, fExec: null, createElFn: null, appendFn: null, cwGet: null, cleanup };
        }
        const parent = typeof document !== "undefined" && document
          ? (_docElGet ? (_reflectApply(_docElGet, document, []) || document.body) : (document.documentElement || document.body))
          : null;
        const createElFn = _docCreateElement || (typeof document !== "undefined" && document ? document.createElement : null);
        const appendFn = _nodeAppendChild || (parent && parent.appendChild);
        if (!parent || typeof createElFn !== "function" || typeof appendFn !== "function") {
          return { ok: false, frame: null, host: null, win: null, fToStr: null, fExec: null, createElFn: null, appendFn: null, cwGet: null, cleanup };
        }
        // Pre-verify captured DOM intrinsics BEFORE creating iframe via RegExp.prototype.exec (immune to RegExp.prototype.test -> exec dispatch!)
        if (
          !isNativeNamed(createElFn, "createElement") ||
          !isNativeNamed(appendFn, "appendChild") ||
          (_elAttachShadow && !isNativeNamed(_elAttachShadow, "attachShadow"))
        ) {
          return { ok: false, frame: null, host: null, win: null, fToStr: null, fExec: null, createElFn, appendFn, cwGet: null, cleanup };
        }
        frame = _reflectApply(createElFn, document, ["iframe"]);
        if (_elAttachShadow) {
          host = _reflectApply(createElFn, document, ["div"]);
          const sd = _objCreate(null);
          sd.mode = "closed";
          const shadow = _reflectApply(_elAttachShadow, host, [sd]);
          if (!shadow || host.shadowRoot) {
            return { ok: false, frame, host, win: null, fToStr: null, fExec: null, createElFn, appendFn, cwGet: null, cleanup };
          }
          _reflectApply(appendFn, parent, [host]);
          _reflectApply(appendFn, shadow, [frame]);
        } else {
          _reflectApply(appendFn, parent, [frame]);
        }
        if (_reflectApply(_hasOwn, frame, ["contentWindow"])) {
          return { ok: false, frame, host, win: null, fToStr: null, fExec: null, createElFn, appendFn, cwGet: null, cleanup };
        }
        if (
          (_Document && (typeof Document !== "function" || Document !== _Document)) ||
          (_Node && (typeof Node !== "function" || Node !== _Node)) ||
          (_Element && (typeof Element !== "function" || Element !== _Element)) ||
          (_HTMLIFrameElement && (typeof HTMLIFrameElement !== "function" || HTMLIFrameElement !== _HTMLIFrameElement))
        ) {
          return { ok: false, frame, host, win: null, fToStr: null, fExec: null, createElFn, appendFn, cwGet: null, cleanup };
        }
        const frameProto = _getProto(frame);
        if (_iframeProto && frameProto !== _iframeProto) {
          return { ok: false, frame, host, win: null, fToStr: null, fExec: null, createElFn, appendFn, cwGet: null, cleanup };
        }
        const cwDesc = frameProto ? _getOwnPropDesc(frameProto, "contentWindow") : null;
        const cwGet = _iframeCwGet || (cwDesc && cwDesc.get) || null;
        if (typeof cwGet !== "function" || !cwDesc || cwDesc.get !== cwGet) {
          return { ok: false, frame, host, win: null, fToStr: null, fExec: null, createElFn, appendFn, cwGet: null, cleanup };
        }
        const fWin = _reflectApply(cwGet, frame, []);
        const fToStr = fWin && fWin.Function && fWin.Function.prototype && fWin.Function.prototype.toString;
        const fExec = fWin && fWin.RegExp && fWin.RegExp.prototype && fWin.RegExp.prototype.exec;
        if (!fWin || fWin === window || typeof fToStr !== "function" || typeof fExec !== "function" || fToStr === _fnToString || fExec === _regexExec) {
          return { ok: false, frame, host, win: fWin, fToStr: null, fExec: null, createElFn, appendFn, cwGet, cleanup };
        }
        // Fail closed if DOM/WebIDL constructors were deleted or replaced before load!
        if (
          (fWin.HTMLIFrameElement && (!_HTMLIFrameElement || typeof HTMLIFrameElement !== "function")) ||
          (fWin.Element && (!_Element || typeof Element !== "function")) ||
          (fWin.Document && (!_Document || typeof Document !== "function")) ||
          (fWin.Node && (!_Node || typeof Node !== "function")) ||
          (fWin.Response && (!_Response || typeof Response !== "function")) ||
          (fWin.ArrayBuffer && (!_ArrayBuffer || typeof ArrayBuffer !== "function")) ||
          (fWin.CryptoKey && (!_CryptoKey || typeof CryptoKey !== "function")) ||
          (fWin.Element && fWin.Element.prototype && typeof fWin.Element.prototype.attachShadow === "function" && !_elAttachShadow)
        ) {
          return { ok: false, frame, host, win: fWin, fToStr: null, fExec: null, createElFn, appendFn, cwGet, cleanup };
        }
        if (!_elAttachShadow) {
          const probeDiv = _reflectApply(createElFn, document, ["div"]);
          if (probeDiv && typeof probeDiv.attachShadow === "function") {
            return { ok: false, frame, host, win: fWin, fToStr: null, fExec: null, createElFn, appendFn, cwGet, cleanup };
          }
        }
        if (!isNativeNamed(fToStr, "toString") || !isNativeNamed(fExec, "exec")) {
          return { ok: false, frame, host, win: fWin, fToStr, fExec, createElFn, appendFn, cwGet, cleanup };
        }
        return { ok: true, tampered: false, frame, host, win: fWin, fToStr, fExec, createElFn, appendFn, cwGet, cleanup };
      } catch (_) {
        return { ok: false, tampered: true, frame, host, win: null, fToStr: null, fExec: null, createElFn: null, appendFn: null, cwGet: null, cleanup };
      }
    }

    function verifyAllIntrinsicsWithRealm(fToStr, fExec, createElFn, appendFn, cwGet, fWin = null, skipSharedCore = false) {
      // Use untouched fresh-realm Reflect.apply whenever fWin is available so a hooked main-realm _reflectApply cannot spoof its own verification!
      const fApply = fWin && fWin.Reflect && typeof fWin.Reflect.apply === "function" ? fWin.Reflect.apply : _reflectApply;
      if (fWin && fWin.Reflect && typeof fWin.Reflect.apply === "function") {
        if (fApply === _reflectApply || !isNativeNamed(fApply, "apply", fToStr, fExec, fApply)) return false;
      }
      if (fWin) {
        if (
          (fWin.Document && (!_Document || typeof Document !== "function")) ||
          (fWin.Node && (!_Node || typeof Node !== "function")) ||
          (fWin.Response && (!_Response || typeof Response !== "function")) ||
          (fWin.ArrayBuffer && (!_ArrayBuffer || typeof ArrayBuffer !== "function")) ||
          (fWin.CryptoKey && (!_CryptoKey || typeof CryptoKey !== "function")) ||
          (REQUIRE_GUARD_INTEGRITY && fWin.XMLHttpRequest && (!OrigXHR || typeof XMLHttpRequest !== "function"))
        ) {
          return false;
        }
        if (fWin.Response && fWin.Response.prototype) {
          const frp = fWin.Response.prototype;
          if (
            (typeof frp.json === "function" && !_ResponseJson) ||
            (typeof frp.clone === "function" && !_respClone) ||
            (typeof frp.arrayBuffer === "function" && !_respArrayBuffer) ||
            (_getOwnPropDesc(frp, "status")?.get && !_respStatusGet) ||
            (_getOwnPropDesc(frp, "headers")?.get && !_respHeadersGet)
          ) {
            return false;
          }
        }
      }
      if (hasProtoIndexPollution(_getOwnPropertyNames, fExec, fApply)) return false;
      // When skipSharedCore is true (called from embedded VeilBreak's openVerifiedFreshRealm), NEVER blindly trust ProxySnare's separately-captured closures:
      // verify O(1) strict === identity between every skipped ProxySnare closure and the live global/prototype already proven native by VeilBreak!
      if (skipSharedCore) {
        if (
          _reflectApply !== Reflect.apply ||
          _String !== String ||
          _Uint8Array !== Uint8Array ||
          _Int32Array !== Int32Array ||
          _MathRound !== Math.round ||
          _MathMax !== Math.max ||
          _MathFloor !== Math.floor ||
          _MathClz32 !== Math.clz32 ||
          _fnCall !== Function.prototype.call ||
          _fnApply !== Function.prototype.apply ||
          _fnBind !== Function.prototype.bind ||
          _fnToString !== Function.prototype.toString ||
          _regexExec !== RegExp.prototype.exec ||
          _regexTest !== RegExp.prototype.test ||
          _strReplace !== String.prototype.replace ||
          _strTrim !== String.prototype.trim ||
          _strSplit !== String.prototype.split ||
          _strIncludes !== String.prototype.includes ||
          _strStartsWith !== String.prototype.startsWith ||
          _strEndsWith !== String.prototype.endsWith ||
          _strToLower !== String.prototype.toLowerCase ||
          _strToUpper !== String.prototype.toUpperCase ||
          _rawDateNow !== Date.now ||
          _strCharCodeAt !== String.prototype.charCodeAt ||
          _strCharAt !== String.prototype.charAt ||
          _strSlice !== String.prototype.slice ||
          _strIndexOf !== String.prototype.indexOf ||
          _defineProperty !== Object.defineProperty ||
          _objCreate !== Object.create ||
          _getOwnPropertyNames !== Object.getOwnPropertyNames ||
          _getOwnPropDesc !== Object.getOwnPropertyDescriptor ||
          _hasOwn !== Object.prototype.hasOwnProperty ||
          _getProto !== Object.getPrototypeOf ||
          _jsonStringify !== JSON.stringify ||
          (_regexSymReplace && typeof Symbol === "function" && Symbol.replace && _regexSymReplace !== RegExp.prototype[Symbol.replace]) ||
          (_rawPerfNow && typeof Performance !== "undefined" && Performance.prototype && typeof Performance.prototype.now === "function" && _rawPerfNow !== Performance.prototype.now) ||
          (_encode && typeof TextEncoder !== "undefined" && TextEncoder.prototype && _encode !== TextEncoder.prototype.encode)
        ) {
          return false;
        }
      }
      // Entries: [fn, expectedName] copied into null-prototype tables (immune to Array.prototype index setters/getters!)
      const baseNative = skipSharedCore ? [
        [_Error, "Error"],
        [_NativePromise, "Promise"],
        [_nativePromiseThen, "then"],
        [_isArray, "isArray"],
        [Array.isArray, "isArray"],
        [_MathMin, "min"],
        [Math.min, "min"],
        [_strLastIndexOf, "lastIndexOf"],
        [String.prototype.lastIndexOf, "lastIndexOf"],
        [_jsonParse, "parse"],
        [JSON.parse, "parse"],
      ] : [
        [_reflectApply, "apply"],
        [Reflect.apply, "apply"],
        [_Error, "Error"],
        [_String, "String"],
        [String, "String"],
        [_NativePromise, "Promise"],
        [_nativePromiseThen, "then"],
        [_isArray, "isArray"],
        [Array.isArray, "isArray"],
        [_Uint8Array, "Uint8Array"],
        [Uint8Array, "Uint8Array"],
        [_Int32Array, "Int32Array"],
        [_MathRound, "round"],
        [Math.round, "round"],
        [_MathMin, "min"],
        [Math.min, "min"],
        [_MathMax, "max"],
        [Math.max, "max"],
        [_MathFloor, "floor"],
        [_MathClz32, "clz32"],
        [_fnCall, "call"],
        [Function.prototype.call, "call"],
        [_fnApply, "apply"],
        [Function.prototype.apply, "apply"],
        [_fnBind, "bind"],
        [Function.prototype.bind, "bind"],
        [_fnToString, "toString"],
        [Function.prototype.toString, "toString"],
        [_regexExec, "exec"],
        [RegExp.prototype.exec, "exec"],
        [_regexTest, "test"],
        [RegExp.prototype.test, "test"],
        [_strReplace, "replace"],
        [String.prototype.replace, "replace"],
        [_strTrim, "trim"],
        [String.prototype.trim, "trim"],
        [_strSplit, "split"],
        [String.prototype.split, "split"],
        [_strIncludes, "includes"],
        [String.prototype.includes, "includes"],
        [_strStartsWith, "startsWith"],
        [String.prototype.startsWith, "startsWith"],
        [_strEndsWith, "endsWith"],
        [String.prototype.endsWith, "endsWith"],
        [_strToLower, "toLowerCase"],
        [String.prototype.toLowerCase, "toLowerCase"],
        [_strToUpper, "toUpperCase"],
        [String.prototype.toUpperCase, "toUpperCase"],
        [_rawDateNow, "now"],
        [Date.now, "now"],
        [_strCharCodeAt, "charCodeAt"],
        [String.prototype.charCodeAt, "charCodeAt"],
        [_strCharAt, "charAt"],
        [String.prototype.charAt, "charAt"],
        [_strSlice, "slice"],
        [String.prototype.slice, "slice"],
        [_strIndexOf, "indexOf"],
        [String.prototype.indexOf, "indexOf"],
        [_strLastIndexOf, "lastIndexOf"],
        [String.prototype.lastIndexOf, "lastIndexOf"],
        [_defineProperty, "defineProperty"],
        [Object.defineProperty, "defineProperty"],
        [_objCreate, "create"],
        [Object.create, "create"],
        [_getOwnPropertyNames, "getOwnPropertyNames"],
        [Object.getOwnPropertyNames, "getOwnPropertyNames"],
        [_getOwnPropDesc, "getOwnPropertyDescriptor"],
        [Object.getOwnPropertyDescriptor, "getOwnPropertyDescriptor"],
        [_hasOwn, "hasOwnProperty"],
        [Object.prototype.hasOwnProperty, "hasOwnProperty"],
        [_getProto, "getPrototypeOf"],
        [Object.getPrototypeOf, "getPrototypeOf"],
        [_jsonStringify, "stringify"],
        [JSON.stringify, "stringify"],
        [_jsonParse, "parse"],
        [JSON.parse, "parse"],
      ];
      const mnF = _objCreate(null);
      const mnN = _objCreate(null);
      const mnG = _objCreate(null);
      let mnLen = 0;
      const addNative = (fn, name, isGet = false) => {
        mnF[mnLen] = fn;
        mnN[mnLen] = name;
        mnG[mnLen] = Boolean(isGet);
        mnLen += 1;
      };
      for (let i = 0; i < baseNative.length; i++) {
        addNative(baseNative[i][0], baseNative[i][1], false);
      }
      if (!isZoneJsPromiseCtor()) addNative(Promise, "Promise");
      if (createElFn) addNative(createElFn, "createElement");
      if (appendFn) addNative(appendFn, "appendChild");
      if (_promiseSpeciesGet) {
        addNative(_promiseSpeciesGet, "[Symbol.species]", true);
        const liveSpGet = _symSpecies ? _getOwnPropDesc(_NativePromise, _symSpecies)?.get : null;
        addNative(liveSpGet, "[Symbol.species]", true);
      }
      if (_arrayIter) {
        addNative(_arrayIter, "values");
        if (_symIterator) {
          const aiDesc = _getOwnPropDesc(_arrProto, _symIterator);
          if (!aiDesc || aiDesc.get || aiDesc.set) return false;
          addNative(aiDesc.value, "values");
        }
      }
      if (_arrayValues) {
        addNative(_arrayValues, "values");
        const avDesc = _getOwnPropDesc(_arrProto, "values");
        if (!avDesc || avDesc.get || avDesc.set) return false;
        addNative(avDesc.value, "values");
      }
      if (_arrIterNext && _arrIterProto) {
        addNative(_arrIterNext, "next");
        const anDesc = _getOwnPropDesc(_arrIterProto, "next");
        if (!anDesc || anDesc.get || anDesc.set) return false;
        addNative(anDesc.value, "next");
      }
      if (!skipSharedCore && _regexSymReplace) {
        addNative(_regexSymReplace, "[Symbol.replace]");
        if (_symReplace) addNative(_regExpProto[_symReplace], "[Symbol.replace]");
      }
      // Check load-time captured I/O & crypto/timing intrinsics (catches pre-load hooks while staying 0-FP on post-load RUM/APM wrappers!)
      if (_ResponseJson) addNative(_ResponseJson, "json");
      if (_respClone) addNative(_respClone, "clone");
      if (_respArrayBuffer) addNative(_respArrayBuffer, "arrayBuffer");
      if (_respStatusGet) addNative(_respStatusGet, "status", true);
      if (_respHeadersGet) addNative(_respHeadersGet, "headers", true);
      if (_respRedirectedGet) addNative(_respRedirectedGet, "redirected", true);
      if (_respUrlGet) addNative(_respUrlGet, "url", true);
      if (_respTypeGet) addNative(_respTypeGet, "type", true);
      // Gate pre-load fetch/XHR native-code checks on REQUIRE_GUARD_INTEGRITY so balanced/requireGuardIntegrity:false
      // tolerates pre-loaded Sentry/Datadog RUM while keeping Promise, SubtleCrypto, crypto, JSON & core JS intrinsics strict!
      if (REQUIRE_GUARD_INTEGRITY) {
        if (_rawFetch) addNative(_rawFetch, "fetch");
        if (OrigXHR) addNative(OrigXHR, "XMLHttpRequest");
        if (origOpen) addNative(origOpen, "open");
        if (origSend) addNative(origSend, "send");
        if (origSetHdr) addNative(origSetHdr, "setRequestHeader");
      }
      if (_getRandomValues) addNative(_getRandomValues, "getRandomValues");
      if (_perfGetEntriesByType) addNative(_perfGetEntriesByType, "getEntriesByType");
      if (!skipSharedCore && _rawPerfNow) {
        addNative(_rawPerfNow, "now");
        if (typeof performance !== "undefined" && typeof performance.now === "function") addNative(performance.now, "now");
        if (typeof Performance !== "undefined" && Performance.prototype && typeof Performance.prototype.now === "function") addNative(Performance.prototype.now, "now");
      }
      if (_xhrReadyStateGet) addNative(_xhrReadyStateGet, "readyState", true);
      if (_xhrStatusGet) addNative(_xhrStatusGet, "status", true);
      if (_xhrResponseUrlGet) addNative(_xhrResponseUrlGet, "responseURL", true);
      if (_xhrGetRespHdr) addNative(_xhrGetRespHdr, "getResponseHeader");
      if (!skipSharedCore && _encode) {
        addNative(_encode, "encode");
        if (typeof TextEncoder !== "undefined" && TextEncoder.prototype) addNative(TextEncoder.prototype.encode, "encode");
      }
      // Always verify ProxySnare's own captured DOM/Headers closures (VeilBreak does NOT check live Headers.prototype/DOM against ProxySnare!)
      if (_hdrSet) addNative(_hdrSet, "set");
      if (_hdrGet) addNative(_hdrGet, "get");
      if (_hdrHas) addNative(_hdrHas, "has");
      if (!cwGet) return false;
      addNative(cwGet, "contentWindow", true);
      if (_docElGet) addNative(_docElGet, "documentElement", true);
      if (_elGetAttr) addNative(_elGetAttr, "getAttribute");
      if (_elAttachShadow) addNative(_elAttachShadow, "attachShadow");
      addNative(_URL, "URL");
      addNative(URL, "URL");
      if (_urlOriginGet) addNative(_urlOriginGet, "origin", true);
      if (_urlPathnameGet) addNative(_urlPathnameGet, "pathname", true);
      if (_callSiteCaptureTampered) return false;
      let fWinHasV8CallSites = _hasV8ErrorHeader;
      if (!fWinHasV8CallSites && fWin && fWin.Error && fWin.Error.prototype && !_getOwnPropDesc(fWin.Error.prototype, "stack")) {
        try {
          const prevFPst = fWin.Error.prepareStackTrace;
          fWin.Error.prepareStackTrace = _capSites;
          const fSites = new fWin.Error().stack;
          fWin.Error.prepareStackTrace = prevFPst;
          if (_isArray(fSites) && fSites.length > 0 && fSites[0] && typeof fSites[0].getFileName === "function" && typeof fSites[0].isEval === "function") {
            fWinHasV8CallSites = true;
          }
        } catch (_) {}
      }
      if (fWinHasV8CallSites && (!_callSiteProto || !_csGetFileName || !_csIsEval)) return false;
      if (_callSiteProto) {
        if (_csGetFileName) addNative(_csGetFileName, "getFileName");
        if (_csGetSrcUrl) addNative(_csGetSrcUrl, "getScriptNameOrSourceURL");
        if (_csIsEval) addNative(_csIsEval, "isEval");
        if (_csIsNative) addNative(_csIsNative, "isNative");
        if (_csIsPromiseAll) addNative(_csIsPromiseAll, "isPromiseAll");
        if (_csGetFnName) addNative(_csGetFnName, "getFunctionName");
        if (_csToString) addNative(_csToString, "toString");
      }
      let checkInstStackGet = null;
      if (fWin && fWin.Error && fWin.Error.prototype) {
        const freshErrProtoHasStack = Boolean(_getOwnPropDesc(fWin.Error.prototype, "stack"));
        if (freshErrProtoHasStack) {
          // Gecko/WebKit: Error.prototype MUST have native named 'stack' getter (catches pre-load delete Error.prototype.stack & .bind(null)!)
          const curProtoGet = _getOwnPropDesc(_Error.prototype, "stack")?.get;
          if (!_errProtoStackGet || curProtoGet !== _errProtoStackGet) return false;
          addNative(_errProtoStackGet, "stack", true);
        } else {
          // V8: Error.prototype has NO own 'stack' accessor natively (catches pre-load/post-load Object.defineProperty(Error.prototype, 'stack', ...))
          if (_errProtoStackGet || _getOwnPropDesc(_Error.prototype, "stack")) return false;
          const freshInstHasStack = Boolean(_getOwnPropDesc(new fWin.Error(), "stack")?.get);
          if (freshInstHasStack) {
            const curInstGet = _getOwnPropDesc(new _Error(), "stack")?.get;
            if (!_errInstStackGet || curInstGet !== _errInstStackGet) return false;
            checkInstStackGet = _errInstStackGet;
          }
        }
      } else if (_errStackGet) {
        if (_errProtoStackGet) {
          const curProtoGet = _getOwnPropDesc(_Error.prototype, "stack")?.get;
          if (curProtoGet !== _errProtoStackGet) return false;
          addNative(_errProtoStackGet, "stack", true);
        } else {
          const curInstGet = _getOwnPropDesc(new _Error(), "stack")?.get;
          if (curInstGet !== _errInstStackGet) return false;
          checkInstStackGet = _errInstStackGet;
        }
      }
      if (checkInstStackGet && (typeof checkInstStackGet !== "function" || fApply(fExec, _ERR_INST_STACK_GET_RE, [fApply(fToStr, checkInstStackGet, [])]) === null)) {
        return false;
      }
      for (let i = 0; i < mnLen; i++) {
        if (!isNativeNamed(mnF[i], mnN[i], fToStr, fExec, fApply, mnG[i])) {
          return false;
        }
      }
      return true;
    }

    function openVerifiedFreshRealm() {
      const base = openBaseFreshRealm();
      if (!base.ok) return base;
      try {
        if (!verifyAllIntrinsicsWithRealm(base.fToStr, base.fExec, base.createElFn, base.appendFn, base.cwGet, base.win)) {
          return { ok: false, frame: base.frame, host: base.host, win: base.win, fToStr: base.fToStr, fExec: base.fExec, cleanup: base.cleanup };
        }
        return base;
      } catch (_) {
        return { ok: false, frame: base.frame, host: base.host, win: null, fToStr: null, fExec: null, cleanup: base.cleanup };
      }
    }

    let lastIframeConsoleProbeTs = -1;
    let lastIframeConsoleRes = { tripped: false, ok: false };
    function probeCdpWithNativeConsole(bypassIframeThrottle = false) {
      if (_consoleDebug) {
        try {
          let tripped = false;
          const e = new _Error();
          _defGet(e, "stack", () => { tripped = true; return ""; });
          _consoleDebug(e);
          return { tripped, ok: true };
        } catch (_) {
          return { tripped: false, ok: false };
        }
      }
      // Check throttle cache BEFORE allocating Error() (zero wasted allocations when Sentry wraps console.debug!)
      const now = monoNow();
      const iframeThrottleMs = ALLOW_DEVTOOLS ? 30_000 : 2_500;
      if (!bypassIframeThrottle && lastIframeConsoleRes.ok && lastIframeConsoleProbeTs >= 0 && (now - lastIframeConsoleProbeTs) < iframeThrottleMs) {
        return lastIframeConsoleRes;
      }
      // Minimal 6-intrinsic iframe verification for periodic RUM-wrapped console.debug probes!
      const realm = openBaseFreshRealm();
      try {
        if (realm.ok && realm.win && realm.win.console && typeof realm.win.console.debug === "function") {
          const fDbg = realm.win.console.debug;
          if (fDbg.name === "debug" && isNativeNamed(fDbg, "debug", realm.fToStr, realm.fExec)) {
            let tripped = false;
            const e = new _Error();
            _defGet(e, "stack", () => { tripped = true; return ""; });
            _reflectApply(fDbg, realm.win.console, [e]);
            lastIframeConsoleProbeTs = now;
            lastIframeConsoleRes = { tripped, ok: true };
            return lastIframeConsoleRes;
          }
        }
      } catch (_) {
      } finally {
        if (realm && realm.cleanup) realm.cleanup();
      }
      return { tripped: false, ok: false };
    }

    function hasAutomationGlobals(fullScan) {
      for (let i = 0; i < _FAST_AUTOMATION_KEYS.length; i++) {
        const k = _FAST_AUTOMATION_KEYS[i];
        if (k in window) return true;
        if (typeof document !== "undefined" && document && (k in document)) return true;
      }
      if (!fullScan) return false;
      const keys = _getOwnPropertyNames(window);
      for (let i = 0; i < keys.length; i++) {
        if (rxTest(_SUS_AUTOMATION_RE, keys[i])) return true;
      }
      if (typeof document !== "undefined" && document) {
        const dKeys = _getOwnPropertyNames(document);
        for (let i = 0; i < dKeys.length; i++) {
          if (rxTest(_SUS_AUTOMATION_RE, dKeys[i])) return true;
        }
      }
      return false;
    }

    function detectCdpActive(opts = false) {
      const isObj = opts && typeof opts === "object";
      const skipCache = isObj ? Boolean(opts.skipCache) : Boolean(opts);
      const allowFullScan = isObj ? Boolean(opts.allowFullScan) : Boolean(opts);
      const bypassIframeThrottle = isObj ? !Boolean(opts.respectIframeThrottle) : Boolean(opts);
      const now = monoNow();
      const ttl = cachedCdp.active || ALLOW_DEVTOOLS ? 15_000 : 2_000;
      if (!skipCache && cachedCdp.ts >= 0 && now >= cachedCdp.ts && (now - cachedCdp.ts) < ttl) return cachedCdp.active;
      let active = false;
      try {
        const probe = probeCdpWithNativeConsole(bypassIframeThrottle);
        // If console.debug / Error.stack defineProperty failed even in a clean iframe realm, fail closed when !ALLOW_DEVTOOLS || BLOCK_CONSOLE_EVAL!
        if (probe.tripped || (!probe.ok && (!ALLOW_DEVTOOLS || BLOCK_CONSOLE_EVAL))) active = true;
      } catch (_) {
        if (!ALLOW_DEVTOOLS || BLOCK_CONSOLE_EVAL) active = true;
      }
      if (!active) {
        try {
          if (Boolean(navigator && navigator.webdriver)) active = true;
        } catch (_) {}
      }
      if (!active) {
        try {
          const needFull = allowFullScan || lastFullScanTs < 0 || (now - lastFullScanTs) >= 30_000;
          if (needFull) lastFullScanTs = now;
          if (hasAutomationGlobals(needFull)) active = true;
        } catch (_) {}
      }
      if (active) cdpEverDetected = true;
      cachedCdp = { ts: now, active };
      return active;
    }

    function captureConsoleEvalFlag() {
      if (ALLOW_DEVTOOLS && !BLOCK_CONSOLE_EVAL && !COLLECT_CE_TELEMETRY) return 0;
      try {
        // Lazily discover <script> tags & inline scripts parsed up to this point before DOMContentLoaded/complete (100ms throttled; locks once readyState !== "loading"!)
        if (_needScriptUrlTracking && !domLoadedSeeded) {
          seedInitialScriptOrigins();
        }
        const strictCdpMode = BLOCK_CDP_ACTIVE && !ALLOW_DEVTOOLS;
        // Coalesce native main-realm CDP probes over 250ms & honor ALLOW_DEVTOOLS 15s TTL (zero Promise.all burst spam!)
        const needFreshCdp =
          (!ALLOW_DEVTOOLS || BLOCK_CONSOLE_EVAL) &&
          Boolean(_consoleDebug) &&
          !cachedCdp.active &&
          !(strictCdpMode && cdpEverDetected) &&
          (cachedCdp.ts < 0 || (monoNow() - cachedCdp.ts) >= 250);
        let cdpNow = (ALLOW_DEVTOOLS && !BLOCK_CONSOLE_EVAL)
          ? cachedCdp.active
          : (needFreshCdp
              ? detectCdpActive({ skipCache: true, allowFullScan: false, respectIframeThrottle: true })
              : detectCdpActive(false));
        const cdpFlaggedInitial = cdpNow || (strictCdpMode && cdpEverDetected);
        // Check Error.prototype.stack (Gecko/WebKit) OR V8 instance Error.stack getter, AND detect locked/inherited/accessor Error.prepareStackTrace & Error.stackTraceLimit!
        const pstDesc = _getOwnPropDesc(_Error, "prepareStackTrace");
        const pstInherited = !pstDesc && ("prepareStackTrace" in _Error);
        const pstLocked = Boolean(
          pstInherited ||
          (pstDesc && !pstDesc.configurable && (!pstDesc.writable || pstDesc.get || pstDesc.set))
        );
        const stlDesc = _getOwnPropDesc(_Error, "stackTraceLimit");
        const stlInherited = _hasInitialStackTraceLimit && !stlDesc && ("stackTraceLimit" in _Error);
        const stlIsAccessor = Boolean(stlDesc && (stlDesc.get || stlDesc.set));
        const stlVal = typeof _Error.stackTraceLimit === "number" ? _Error.stackTraceLimit : NaN;
        const stlLockedLow = Boolean(
          stlInherited ||
          (stlDesc && !stlDesc.configurable && (stlIsAccessor || (!stlDesc.writable && !(stlVal >= 64))))
        );
        const errStackTampered = Boolean(
          (_errProtoStackGet && _getOwnPropDesc(_Error.prototype, "stack")?.get !== _errProtoStackGet) ||
          (!_errProtoStackGet && _getOwnPropDesc(_Error.prototype, "stack")) ||
          pstLocked ||
          stlLockedLow ||
          stlIsAccessor
        );
        const stlInvalid = (stlVal !== Infinity && !Number.isFinite(stlVal)) || !(stlVal >= 4);
        const stackTampered =
          errStackTampered ||
          (_hasInitialStackTraceLimit && stlInvalid) ||
          (stlDesc && stlInvalid);
        if (stackTampered && !cdpNow) {
          cdpNow = detectCdpActive({ skipCache: true, allowFullScan: false, respectIframeThrottle: false });
        }
        if (stackTampered && (cdpNow || cdpEverDetected || errStackTampered)) return 1;
        // On V8, use structured CallSite.prototype.getFileName()/isEval() via temporary Error.prepareStackTrace so //# sourceURL=<verified_url>
        // CANNOT spoof Console / Runtime.evaluate / eval() provenance; fall back to formatted stack parsing on Gecko/WebKit!
        const useV8CallSites = Boolean(_hasV8ErrorHeader && _callSiteProto && _csGetFileName && _csIsEval && !pstLocked);
        let rawStack = "";
        let rawSites = null;
        let instStackBad = false;
        let clearedByDefProp = false;
        let clearedByAssign = false;
        let savedPst;
        const hadOwnPst = Boolean(pstDesc);
        let raisedStlDefProp = false;
        let raisedStlAssign = false;
        let savedStl;
        try {
          if (useV8CallSites) {
            if (!pstDesc || (pstDesc.writable && !pstDesc.get && !pstDesc.set)) {
              savedPst = _Error.prepareStackTrace;
              _Error.prepareStackTrace = _capSites;
              clearedByAssign = true;
            } else if (pstDesc.configurable) {
              _defData(_Error, "prepareStackTrace", _capSites, true, true);
              clearedByDefProp = true;
            }
          } else if (pstDesc && !pstLocked) {
            if (pstDesc.writable && !pstDesc.get && !pstDesc.set) {
              savedPst = _Error.prepareStackTrace;
              _Error.prepareStackTrace = undefined;
              clearedByAssign = true;
            } else if (pstDesc.configurable) {
              _defData(_Error, "prepareStackTrace", undefined, true, true);
              clearedByDefProp = true;
            }
          }
          if (_hasInitialStackTraceLimit && (!(stlVal >= 64) || stlIsAccessor)) {
            if (!stlDesc || (stlDesc.writable && !stlIsAccessor)) {
              savedStl = _Error.stackTraceLimit;
              _Error.stackTraceLimit = 64;
              raisedStlAssign = true;
            } else if (stlDesc.configurable) {
              _defData(_Error, "stackTraceLimit", 64, true, true);
              raisedStlDefProp = true;
            }
          }
          const errObj = new _Error();
          // Pin own name/message ONLY on formatted-string stacks (V8 CallSite prepareStackTrace never reads errObj.name/message!)
          if (!useV8CallSites) {
            _defData(errObj, "name", "Error", true, true);
            _defData(errObj, "message", "", true, true);
          }
          if (_errInstStackGet) {
            const instGet = _getOwnPropDesc(errObj, "stack")?.get;
            if (instGet !== _errInstStackGet) instStackBad = true;
          }
          const stVal = _errStackGet ? _reflectApply(_errStackGet, errObj, []) : errObj.stack;
          if (useV8CallSites) rawSites = stVal;
          else rawStack = stVal;
        } finally {
          if (raisedStlAssign) {
            try { _Error.stackTraceLimit = savedStl; } catch (_) {}
          } else if (raisedStlDefProp) {
            try { _defineProperty(_Error, "stackTraceLimit", _copyNullDesc(stlDesc)); } catch (_) {}
          }
          if (clearedByAssign) {
            // Assign undefined instead of delete to keep Error out of V8 dictionary mode on hot API paths!
            try { _Error.prepareStackTrace = hadOwnPst ? savedPst : undefined; } catch (_) {}
          } else if (clearedByDefProp) {
            try { _defineProperty(_Error, "prepareStackTrace", _copyNullDesc(pstDesc)); } catch (_) {}
          }
        }
        if (instStackBad) return 1;
        const guardMarker = BASE + "/guard.js";
        const curOrigin = window.location && window.location.origin ? window.location.origin : "";
        const guardExactUrl = curOrigin ? (curOrigin + guardMarker) : "";
        // Gate standalone webpack:// exemptions strictly on ALLOW_DEVTOOLS && !BLOCK_CONSOLE_EVAL so
        // //# sourceURL=webpack:// can NEVER bypass blockConsoleEval:true (real app-parented Webpack eval still passes via parent http(s) script!).
        const allowWebpackDev = ALLOW_DEVTOOLS && !BLOCK_CONSOLE_EVAL;
        let hasAnyAnon = false;
        let hasEval = false;
        let hasWebpackDev = false;
        let hasDisallowedWebpack = false;
        let bottomIsBareTop = false;
        let hasVerifiedAppUrl = false;
        let hasVerifiedNonDocScript = false;
        let hasUnverifiedFrame = false;
        let allEvalLinesAppParented = true;
        let hasUnparentedAnon = false;

        if (useV8CallSites) {
          // Direct structured V8 CallSite evaluation: zero fake-string round-tripping, lazy toString/getFunctionName,
          // null-prototype indexed containers (immune to Array.prototype/Object.prototype setters!), and NEVER trusts spoofable getEvalOrigin()!
          if (!_isArray(rawSites)) return 1;
          const callerSites = _objCreate(null);
          let cLen = 0;
          let seenTop = 0;
          let sawInternalTop = false;
          let inLeadingGuard = true;
          for (let i = 0; i < rawSites.length; i++) {
            if (!_reflectApply(_hasOwn, rawSites, [i])) return 1;
            const s = rawSites[i];
            if (!s || typeof s !== "object" || _getProto(s) !== _callSiteProto) return 1;
            const file = _reflectApply(_csGetFileName, s, []);
            let isGuardFrame = false;
            if (inLeadingGuard && seenTop < 2) {
              if (typeof file === "string" && file.length > 0) {
                const cleanTop = stripUrlQueryHash(file);
                if ((guardExactUrl && cleanTop === guardExactUrl) || (!guardExactUrl && _reflectApply(_strIncludes, cleanTop, [guardMarker]))) {
                  isGuardFrame = true;
                }
              }
              if (!isGuardFrame) {
                const topFn = _csGetFnName ? _reflectApply(_csGetFnName, s, []) : null;
                if (topFn === "captureConsoleEvalFlag" || topFn === "proxySnareFetch" || topFn === "proxySnareXhrSend") {
                  isGuardFrame = true;
                }
              }
            }
            seenTop += 1;
            if (isGuardFrame) {
              sawInternalTop = true;
              continue;
            }
            inLeadingGuard = false;
            const isEv = Boolean(_reflectApply(_csIsEval, s, []));
            const isNat = Boolean(_csIsNative && _reflectApply(_csIsNative, s, []));
            const isPa = Boolean(_csIsPromiseAll && _reflectApply(_csIsPromiseAll, s, []));
            const rec = _objCreate(null);
            rec.s = s;
            rec.file = file;
            rec.isEv = isEv;
            rec.isNat = isNat;
            rec.isPa = isPa;
            rec.isWp = false;
            rec.isExt = false;
            rec.isV8AsyncComb = false;
            rec.isV8Builtin = false;
            rec.isAnon = false;
            callerSites[cLen++] = rec;
          }
          if (!sawInternalTop && (cdpNow || cdpEverDetected || !ALLOW_DEVTOOLS || BLOCK_CONSOLE_EVAL)) return 1;
          if (cLen === 0) {
            // Fail closed on zero-caller-frame console callbacks (e.g. Promise.resolve(url).then(fetch), setTimeout(fetch, ...))!
            if (BLOCK_CONSOLE_EVAL) return 1;
            if (!cdpNow) cdpNow = detectCdpActive({ skipCache: true, allowFullScan: false, respectIframeThrottle: false });
            return (cdpNow || cdpEverDetected || stackTampered) ? 1 : 0;
          }
          let prevCleanFile = "";
          for (let i = 0; i < cLen; i++) {
            const rec = callerSites[i];
            const f = rec.file;
            if (!rec.isEv && !rec.isNat && !rec.isPa && typeof f === "string" && f.length > 0 && f === prevCleanFile) {
              continue;
            }
            if (typeof f === "string" && f.length > 0) {
              if (rxTest(_EXPLICIT_EVAL_RE, f)) return 1;
            }
            if (rec.isEv) {
              hasEval = true;
              const su = _csGetSrcUrl ? _reflectApply(_csGetSrcUrl, rec.s, []) : null;
              if (typeof su === "string" && su.length > 0) {
                if (rxTest(_EXPLICIT_EVAL_RE, su)) return 1;
                if (rxTest(_WEBPACK_DEV_RE, su) && allowWebpackDev) {
                  rec.isWp = true;
                  hasWebpackDev = true;
                }
              }
            } else if (rec.isPa) {
              rec.isV8AsyncComb = true;
            } else if (rec.isNat) {
              // Native C++ host frame
            } else if (typeof f === "string" && f.length > 0) {
              if (rxTest(_WEBPACK_DEV_RE, f)) {
                if (allowWebpackDev) { rec.isWp = true; hasWebpackDev = true; }
                else hasDisallowedWebpack = true;
              } else if (rxTest(_EXT_SCHEME_RE, f)) {
                rec.isExt = true;
              } else if (f === "<anonymous>" || f === "evalmachine.<anonymous>" || rxTest(_ANON_FRAME_RE, f)) {
                rec.isAnon = true;
                hasAnyAnon = true;
              } else {
                prevCleanFile = f;
              }
            } else {
              // Empty/null/undefined file on non-eval frame: NEVER classify as webpack (Console/Runtime.evaluate only!).
              const su = _csGetSrcUrl ? _reflectApply(_csGetSrcUrl, rec.s, []) : null;
              if (typeof su === "string" && su.length > 0) {
                if (rxTest(_EXPLICIT_EVAL_RE, su)) return 1;
                if (rxTest(_WEBPACK_DEV_RE, su) && !allowWebpackDev) hasDisallowedWebpack = true;
                rec.isAnon = true;
                hasAnyAnon = true;
              } else if (f === null && su === null && _csToString) {
                const sStr = "at " + _String(_reflectApply(_csToString, rec.s, []));
                if (rxTest(_V8_ASYNC_PROMISE_COMB_RE, sStr)) {
                  rec.isV8AsyncComb = true;
                } else if (i < cLen - 1 && rxTest(_V8_NATIVE_BUILTIN_FRAME_RE, sStr)) {
                  rec.isV8Builtin = true;
                } else {
                  rec.isAnon = true;
                  hasAnyAnon = true;
                }
              } else {
                rec.isAnon = true;
                hasAnyAnon = true;
              }
            }
          }
          if (!cdpFlaggedInitial && !hasAnyAnon && !hasEval && ALLOW_DEVTOOLS && !BLOCK_CONSOLE_EVAL) return 0;

          const isBareTopSite = (rec) => {
            if (rec.isEv || rec.isNat || rec.isExt || rec.isV8AsyncComb || rec.isV8Builtin || rec.isAnon) return false;
            const hasUrlFile = (typeof rec.file === "string" && rxTest(_HTTP_URL_PREFIX_RE, rec.file)) || rec.isWp;
            if (!hasUrlFile) return false;
            const fnName = _csGetFnName ? _reflectApply(_csGetFnName, rec.s, []) : null;
            return !fnName;
          };
          bottomIsBareTop = isBareTopSite(callerSites[cLen - 1]);
          hasUnverifiedFrame = hasDisallowedWebpack;
          let lastVerifiedNonEvalIdx = -1;
          let maxEvalIdx = -1;
          let maxV8NativeAnonIdx = -1;
          let maxExtIdx = -1;
          let lastVerifiedClean = "";
          const allowRedirectHeuristic = !cdpFlaggedInitial;
          const allowConfirmedRedirectOnly = !cdpFlaggedInitial || !strictCdpMode;
          const crossOriginPolicy = !cdpFlaggedInitial
            ? 2
            : (!strictCdpMode && !hasAnyAnon && !hasEval ? 1 : 0);
          for (let i = 0; i < cLen; i++) {
            const rec = callerSites[i];
            if (rec.isWp || rec.isNat || rec.isV8AsyncComb) continue;
            if (rec.isEv) {
              maxEvalIdx = i;
              continue;
            }
            if (rec.isExt) {
              maxExtIdx = i;
              continue;
            }
            if (rec.isV8Builtin) {
              maxV8NativeAnonIdx = i;
              continue;
            }
            if (rec.isAnon) {
              hasUnparentedAnon = true;
              continue;
            }
            const f = rec.file;
            if (typeof f === "string" && rxTest(_HTTP_URL_PREFIX_RE, f)) {
              const cleanPart = stripUrlQueryHash(f);
              const isVer =
                (lastVerifiedClean && cleanPart === lastVerifiedClean) ||
                isKnownPageScriptUrl(f, allowRedirectHeuristic, allowConfirmedRedirectOnly, crossOriginPolicy, cleanPart, true);
              if (isVer) {
                lastVerifiedClean = cleanPart;
                hasVerifiedAppUrl = true;
                lastVerifiedNonEvalIdx = i;
                if (!INITIAL_DOC_URL || cleanPart !== INITIAL_DOC_URL) {
                  hasVerifiedNonDocScript = true;
                }
              } else {
                hasUnverifiedFrame = true;
              }
            } else {
              hasUnverifiedFrame = true;
            }
          }
          // Every V8 isEval() frame MUST have a real non-eval verified app frame strictly below it on the call stack!
          // (Defeats nested eval(//# sourceURL=...) -> new Function() -> Promise.then/setTimeout AND stays 0-FP on Alpine/Vue new Function with //# sourceURL=!)
          if (maxEvalIdx >= 0 && maxEvalIdx >= lastVerifiedNonEvalIdx) {
            allEvalLinesAppParented = false;
            hasUnparentedAnon = true;
          }
          // V8 native built-in intermediate frames (Array.map/forEach/reduce, new Promise) require a verified non-eval caller strictly below them!
          if (maxV8NativeAnonIdx >= 0 && maxV8NativeAnonIdx >= lastVerifiedNonEvalIdx) {
            hasUnparentedAnon = true;
          }
          // Browser extension wrapper frames (chrome-extension:// etc.) are permitted ONLY when parented by a verified app frame strictly below them!
          if (maxExtIdx >= 0 && maxExtIdx >= lastVerifiedNonEvalIdx) {
            hasUnverifiedFrame = true;
          }
        } else {
          if (typeof rawStack !== "string" || !rawStack) {
            if (BLOCK_CONSOLE_EVAL) return 1;
            if (!cdpNow) cdpNow = detectCdpActive({ skipCache: true, allowFullScan: false, respectIframeThrottle: false });
            return (cdpNow || cdpEverDetected || stackTampered) ? 1 : 0;
          }
          const rawLines = splitByChar(rawStack, "\\n");
          if (_hasV8ErrorHeader && rawLines.length > 0 && _reflectApply(_strTrim, rawLines[0], []) !== "Error") {
            return 1;
          }
          const callerLines = _objCreate(null);
          let cLen = 0;
          let seenNonError = 0;
          let sawInternalTop = false;
          let inLeadingGuard = true;
          for (let i = 0; i < rawLines.length; i++) {
            const ln = _reflectApply(_strTrim, rawLines[i], []);
            if (!ln || ln === "Error" || _reflectApply(_strStartsWith, ln, ["Error:"])) continue;
            let isGuardFrame = false;
            // Cap leading guard-frame stripping strictly at depth < 2 (captureConsoleEvalFlag + proxySnareFetch/proxySnareXhrSend)
            // so //# sourceURL=<origin>/__proxysnare/guard.js cannot strip caller frames!
            if (inLeadingGuard && seenNonError < 2) {
              const locTop = extractFrameLocation(ln);
              const locUrls = extractFrameUrls(locTop);
              for (let uIdx = 0; uIdx < locUrls.length; uIdx++) {
                const cleanTop = stripUrlQueryHash(locUrls[uIdx]);
                if ((guardExactUrl && cleanTop === guardExactUrl) || (!guardExactUrl && _reflectApply(_strIncludes, cleanTop, [guardMarker]))) {
                  isGuardFrame = true;
                  break;
                }
              }
              if (!isGuardFrame) {
                if (
                  (_hasV8ErrorHeader &&
                    (_reflectApply(_strStartsWith, ln, ["at captureConsoleEvalFlag ("]) ||
                      _reflectApply(_strStartsWith, ln, ["at proxySnareFetch ("]) ||
                      _reflectApply(_strStartsWith, ln, ["at Window.proxySnareFetch ("]) ||
                      _reflectApply(_strStartsWith, ln, ["at proxySnareXhrSend ("]) ||
                      _reflectApply(_strStartsWith, ln, ["at XMLHttpRequest.proxySnareXhrSend ("]))) ||
                  (!_hasV8ErrorHeader &&
                    (_reflectApply(_strStartsWith, ln, ["captureConsoleEvalFlag@"]) ||
                      _reflectApply(_strStartsWith, ln, ["proxySnareFetch@"]) ||
                      _reflectApply(_strStartsWith, ln, ["proxySnareXhrSend@"])))
                ) {
                  isGuardFrame = true;
                }
              }
            }
            seenNonError += 1;
            if (isGuardFrame) {
              sawInternalTop = true;
              continue;
            }
            inLeadingGuard = false;
            callerLines[cLen++] = ln;
          }
          // If top frames lacked our own captureConsoleEvalFlag/guardMarker frame completely, stack was forged!
          if (!sawInternalTop && (cdpNow || cdpEverDetected || !ALLOW_DEVTOOLS || BLOCK_CONSOLE_EVAL)) return 1;
          if (cLen === 0) {
            if (BLOCK_CONSOLE_EVAL) return 1;
            if (!cdpNow) cdpNow = detectCdpActive({ skipCache: true, allowFullScan: false, respectIframeThrottle: false });
            return (cdpNow || cdpEverDetected || stackTampered) ? 1 : 0;
          }
          // Pre-scan Safari/JSC eval markers so nested arrow/named helpers ("@", "foo@") strictly above "eval code@"/"anonymous@" stay 0-FP when app-parented!
          let deepestJscEvalMarkerIdx = -1;
          if (!_hasV8ErrorHeader) {
            for (let i = cLen - 2; i >= 0; i--) {
              const lnM = callerLines[i];
              if (lnM === "anonymous@" || lnM === "eval code@") {
                deepestJscEvalMarkerIdx = i;
                break;
              }
            }
          }
          const callerLocs = _objCreate(null);
          const callerIsV8Builtin = _objCreate(null);
          const callerIsV8AsyncComb = _objCreate(null);
          const callerIsJscEval = _objCreate(null);
          const callerIsDisallowedWp = _objCreate(null);
          const callerIsExt = _objCreate(null);
          for (let i = 0; i < cLen; i++) {
            const ln = callerLines[i];
            const loc = extractFrameLocation(ln);
            callerLocs[i] = loc;
            if (rxTest(_EXPLICIT_EVAL_RE, loc)) return 1;
            const isV8AsyncComb = _hasV8ErrorHeader && rxTest(_V8_ASYNC_PROMISE_COMB_RE, ln);
            callerIsV8AsyncComb[i] = isV8AsyncComb;
            const isV8Builtin = _hasV8ErrorHeader && !isV8AsyncComb && loc === "<anonymous>" && i < cLen - 1 && rxTest(_V8_NATIVE_BUILTIN_FRAME_RE, ln);
            callerIsV8Builtin[i] = isV8Builtin;
            const isJscEval = !_hasV8ErrorHeader && i < cLen - 1 && (
              ln === "anonymous@" ||
              ln === "eval code@" ||
              (deepestJscEvalMarkerIdx >= 0 && i < deepestJscEvalMarkerIdx && !loc && _reflectApply(_strEndsWith, ln, ["@"]))
            );
            callerIsJscEval[i] = isJscEval;
            if (!isV8Builtin && !isV8AsyncComb && !isJscEval && (!loc || rxTest(_ANON_FRAME_RE, loc))) hasAnyAnon = true;
            if (isJscEval || (_hasV8ErrorHeader && rxTest(_AT_EVAL_PREFIX_RE, ln)) || rxTest(_EVAL_FRAME_RE, loc)) hasEval = true;
            const isWpLoc = rxTest(_WEBPACK_DEV_RE, loc);
            if (isWpLoc && allowWebpackDev) hasWebpackDev = true;
            callerIsDisallowedWp[i] = isWpLoc && !allowWebpackDev;
            callerIsExt[i] = rxTest(_EXT_SCHEME_RE, loc);
          }
          if (!cdpFlaggedInitial && !hasAnyAnon && !hasEval && ALLOW_DEVTOOLS && !BLOCK_CONSOLE_EVAL) return 0;

          const bottomFrame = callerLines[cLen - 1];
          bottomIsBareTop = rxTest(_BARE_TOP_FRAME_RE, bottomFrame);
          hasUnverifiedFrame = false;
          let lastVerifiedIdx = -1;
          let maxV8NativeAnonIdx = -1;
          let maxJscEvalIdx = -1;
          let maxDisallowedWpIdx = -1;
          let maxExtIdx = -1;
          let lastVerifiedClean = "";
          const allowRedirectHeuristic = !cdpFlaggedInitial;
          const allowConfirmedRedirectOnly = !cdpFlaggedInitial || !strictCdpMode;
          const crossOriginPolicy = !cdpFlaggedInitial
            ? 2
            : (!strictCdpMode && !hasAnyAnon && !hasEval ? 1 : 0);
          for (let i = 0; i < cLen; i++) {
            const ln = callerLines[i];
            const loc = callerLocs[i];
            const originLoc = unwrapEvalOrigin(loc);
            const isV8Builtin = callerIsV8Builtin[i];
            const isV8AsyncComb = callerIsV8AsyncComb[i];
            const isJscEval = callerIsJscEval[i];
            const isDisallowedWp = callerIsDisallowedWp[i];
            const isExtLn = callerIsExt[i];
            const isAnonLn = isV8Builtin || (hasAnyAnon && (!loc || rxTest(_ANON_FRAME_RE, loc)));
            const isWpLn = allowWebpackDev && rxTest(_WEBPACK_DEV_RE, originLoc);
            const isNativeCodeLoc = originLoc === "[native code]" || isV8AsyncComb;
            const urls = isNativeCodeLoc || isJscEval || isExtLn ? null : extractFrameUrls(originLoc);
            let lineHasVerified = false;
            if (urls) {
              for (let j = 0; j < urls.length; j++) {
                const urlPart = urls[j];
                if (urlPart) {
                  const cleanPart = stripUrlQueryHash(urlPart);
                  const isVer =
                    (lastVerifiedClean && cleanPart === lastVerifiedClean) ||
                    isKnownPageScriptUrl(urlPart, allowRedirectHeuristic, allowConfirmedRedirectOnly, crossOriginPolicy, cleanPart);
                  if (isVer) {
                    lastVerifiedClean = cleanPart;
                    hasVerifiedAppUrl = true;
                    lineHasVerified = true;
                    lastVerifiedIdx = i;
                    if (!INITIAL_DOC_URL || cleanPart !== INITIAL_DOC_URL) {
                      hasVerifiedNonDocScript = true;
                    }
                  }
                }
              }
            }
            const isAppParentedEvalLn = _hasV8ErrorHeader && lineHasVerified && originLoc !== loc && _reflectApply(_strStartsWith, loc, ["eval at "]);
            const isEvalLn = isAppParentedEvalLn || isJscEval || (hasEval && ((_hasV8ErrorHeader && rxTest(_AT_EVAL_PREFIX_RE, ln)) || rxTest(_EVAL_FRAME_RE, loc)));
            if (isEvalLn) hasEval = true;
            if (!lineHasVerified) {
              if (isJscEval) {
                maxJscEvalIdx = i;
              } else if (isExtLn) {
                maxExtIdx = i;
              } else if (isDisallowedWp) {
                // Allow app-parented Webpack eval/sourceURL frames strictly above a verified http(s) parent; block unparented Console webpack://!
                maxDisallowedWpIdx = i;
              } else {
                if (isEvalLn && !isWpLn) allEvalLinesAppParented = false;
                if (isAnonLn && !isWpLn) {
                  if (isV8Builtin) maxV8NativeAnonIdx = i;
                  else hasUnparentedAnon = true;
                } else if (!isWpLn && !isNativeCodeLoc && originLoc) {
                  hasUnverifiedFrame = true;
                }
              }
            } else if (isAnonLn && !isEvalLn) {
              hasUnparentedAnon = true;
            }
          }
          if (maxV8NativeAnonIdx >= 0 && maxV8NativeAnonIdx >= lastVerifiedIdx) {
            hasUnparentedAnon = true;
          }
          if (maxJscEvalIdx >= 0 && maxJscEvalIdx >= lastVerifiedIdx) {
            allEvalLinesAppParented = false;
            hasUnparentedAnon = true;
          }
          if (maxDisallowedWpIdx >= 0 && maxDisallowedWpIdx >= lastVerifiedIdx) {
            hasUnverifiedFrame = true;
          }
          if (maxExtIdx >= 0 && maxExtIdx >= lastVerifiedIdx) {
            hasUnverifiedFrame = true;
          }
        }

        const cdpFlagged = cdpNow || (strictCdpMode && cdpEverDetected);
        // Webpack 5 devtool:'eval'/'eval-source-map' & Vue/Alpine runtime compilers
        const appParentedEval = hasEval && (hasVerifiedAppUrl || hasWebpackDev) && allEvalLinesAppParented;
        const benignWebpackOnly = hasWebpackDev && !hasUnparentedAnon && !hasUnverifiedFrame && (!hasEval || appParentedEval);
        // Catch //# sourceURL=<INITIAL_DOC_URL> or injected inline-handler spoofing whenever page had no initial inline scripts (even when !cdpFlagged on Firefox/Safari!)
        if ((cdpFlagged || BLOCK_CONSOLE_EVAL) && hasVerifiedAppUrl && !hasVerifiedNonDocScript && !hasInitialInlineScripts) {
          return 1;
        }
        if (cdpFlagged) {
          // Only when CDP blocking is enforced (strictCdpMode) and page finished loading, flag bare top-level frames
          // (avoids 403-blocking legitimate SPA Promise.then/setTimeout/addEventListener arrow callbacks under strict+blockCdpActive:false!)
          if (strictCdpMode && typeof document !== "undefined" && document.readyState === "complete" && bottomIsBareTop) {
            return 1;
          }
          // With DevTools/CDP active, flag ANY unparented anonymous Console frame, non-app-parented eval, or unverified script/sourceURL frame!
          if (hasUnparentedAnon || (hasEval && !appParentedEval) || hasUnverifiedFrame || (!hasVerifiedAppUrl && !benignWebpackOnly)) return 1;
          return 0;
        }
        // Even when !cdpFlagged (stealth CDP Runtime.evaluate without Runtime.enable, Firefox/Safari Console, or injected scripts),
        // enforce unparented anonymous, non-app-parented eval, and unverified frames unconditionally whenever BLOCK_CONSOLE_EVAL is enabled!
        if (BLOCK_CONSOLE_EVAL && (hasUnparentedAnon || (hasEval && !appParentedEval) || hasUnverifiedFrame)) {
          return 1;
        }
        // When !cdpFlagged and ZERO verified app frames exist on the stack (including combinator-only Promise.all([p.then(fetch)]) and [native code]-only stacks!):
        // fail closed whenever BLOCK_CONSOLE_EVAL is enabled; otherwise re-probe CDP live!
        if (!hasVerifiedAppUrl && !benignWebpackOnly) {
          if (BLOCK_CONSOLE_EVAL) return 1;
          cdpNow = detectCdpActive({ skipCache: true, allowFullScan: false, respectIframeThrottle: false });
          return (cdpNow || cdpEverDetected) ? 1 : 0;
        }
        return 0;
      } catch (_) {
        return 1;
      }
    }

    function buildRuntimeContextHeader(consoleEvalFlag, gestureAgeAtCall = null, reqMethod = "GET", interactionSnap = undefined, callMonoAtCall = null) {
      const upperM = _reflectApply(_strToUpper, _String(reqMethod || "GET"), []);
      // Skip periodic CDP polling/window scans/fallback iframes in balanced/monitor modes where server ignores cdp!
      let cdp = 0;
      if (!ALLOW_DEVTOOLS || BLOCK_CDP_ACTIVE) {
        const needFresh =
          !ALLOW_DEVTOOLS &&
          Boolean(_consoleDebug) &&
          !cachedCdp.active &&
          !cdpEverDetected &&
          (cachedCdp.ts < 0 || (monoNow() - cachedCdp.ts) >= 250);
        const cdpLive = detectCdpActive(
          needFresh
            ? { skipCache: true, allowFullScan: false, respectIframeThrottle: true }
            : false
        );
        // When !ALLOW_DEVTOOLS, active CDP is sticky for the tab lifecycle (stops deferred setTimeout after closing DevTools!)
        cdp = (cdpLive || (!ALLOW_DEVTOOLS && cdpEverDetected)) ? 1 : 0;
      } else {
        cdp = cachedCdp.active ? 1 : 0;
      }
      const now = monoNow();
      const evalMono = typeof callMonoAtCall === "number" && Number.isFinite(callMonoAtCall) ? callMonoAtCall : now;
      const hasGesture =
        typeof gestureAgeAtCall === "number"
          ? (Number.isFinite(gestureAgeAtCall) && gestureAgeAtCall >= 0)
          : (lastTrustedGestureMs >= 0 && now >= lastTrustedGestureMs);
      const ga = hasGesture
        ? _MathMax(0, _MathMin(999_999, _MathRound(typeof gestureAgeAtCall === "number" ? gestureAgeAtCall : (now - lastTrustedGestureMs))))
        : 999_999;
      const ug = hasGesture && ga <= USER_GESTURE_WINDOW_MS ? 1 : 0;
      let ikPart = "";
      if (upperM !== "GET" && upperM !== "HEAD") {
        try {
          const vb = getTrustedVeilBreak();
          const last = interactionSnap !== undefined ? interactionSnap : (vb && typeof vb.getLastInteraction === "function" ? vb.getLastInteraction() : null);
          if (last) {
            const pType = _reflectApply(_strToLower, _String(last.pointerType || "mouse"), []);
            const isBal = Boolean(vb && vb.mode === "balanced");
            // Evaluate passive programmatic .click() 250ms correlation against callMonoAtCall (frozen BEFORE handshake/queue RTT!)
            const untrustedFresh = !last.passive || (evalMono >= (last.ts || 0) && (evalMono - (last.ts || 0)) <= 250);
            const allowTeleport = !last.passive || (!isBal && (last.consecutiveTeleports || 0) >= 2 && last.dwellMs > 0);
            const bad =
              (last.isTrusted === false && untrustedFresh) ||
              (allowTeleport &&
                last.isTrusted === true &&
                last.detail >= 1 &&
                pType !== "touch" &&
                pType !== "pen" &&
                last.hitExactCenter &&
                last.pointerMoves <= 3 &&
                last.dwellMs > 0 &&
                last.dwellMs < 12);
            ikPart = ";ik=" + (bad ? "1" : "0");
          }
        } catch (_) {}
      }
      return "ce=" + (consoleEvalFlag ? "1" : "0") + ";cdp=" + cdp + ";ug=" + ug + ";ga=" + ga + ikPart;
    }

    function checkGuardIdentityFast() {
      if (_initTampered || !isPromiseIntegrityOk()) return "TAMPERED_GUARD";
      if (_Math.round !== _MathRound || _Math.min !== _MathMin || _Math.max !== _MathMax) return "TAMPERED_GUARD";
      if (_Date.now !== _rawDateNow) return "TAMPERED_GUARD";
      if (
        _rawPerfNow &&
        typeof performance !== "undefined" &&
        (performance.now !== _rawPerfNow ||
          (typeof Performance !== "undefined" && Performance.prototype && Performance.prototype.now !== _rawPerfNow))
      ) {
        return "TAMPERED_GUARD";
      }
      if (_regexSymReplace && _symReplace && _regExpProto[_symReplace] !== _regexSymReplace) {
        return "TAMPERED_GUARD";
      }
      return "";
    }

    function checkSubtleIdentityFast() {
      if (!_subtle || typeof crypto === "undefined" || crypto.subtle !== _subtle || _getProto(_subtle) !== _subtleProto) {
        return "TAMPERED_SUBTLE";
      }
      if (typeof window.SubtleCrypto !== "function" || window.SubtleCrypto.prototype !== _subtleProto) {
        return "TAMPERED_SUBTLE";
      }
      for (let i = 0; i < _SUBTLE_METHODS.length; i++) {
        const m = _SUBTLE_METHODS[i];
        const cap = _capturedSubtle[m];
        const cur = _subtle[m];
        if (typeof cap !== "function" || cur !== cap || _reflectApply(_hasOwn, _subtle, [m]) || _subtleProto[m] !== cap) {
          return "TAMPERED_SUBTLE";
        }
      }
      return "";
    }

    function finalizeGuardHashWithRealm(checkToStr, checkExec, hashSource, fWin = null) {
      const fApply = fWin && fWin.Reflect && typeof fWin.Reflect.apply === "function" ? fWin.Reflect.apply : _reflectApply;
      if (!_SymbolFor || !isNativeNamed(_SymbolFor, "for", checkToStr, checkExec, fApply)) {
        return "TAMPERED_GUARD";
      }
      const subtleErr = checkSubtleIdentityFast();
      if (subtleErr) return subtleErr;
      for (let i = 0; i < _SUBTLE_METHODS.length; i++) {
        const m = _SUBTLE_METHODS[i];
        if (!isNativeNamed(_capturedSubtle[m], m, checkToStr, checkExec, fApply)) {
          return "TAMPERED_SUBTLE";
        }
      }
      if (!hashSource) return "UNPINNED_OK";
      // __psGuardMain is a private immutable lexical function: reuse cached digest once verified via a fresh cross-realm iframe (eliminates redundant pure-JS SHA-256 after 5s!)
      if (_verifiedSourceHash !== null && checkToStr !== _fnToString) return _verifiedSourceHash;
      const digest = sha256WsHexSync(fApply(checkToStr, __psGuardMain, []));
      if (checkToStr !== _fnToString) _verifiedSourceHash = digest;
      return digest;
    }

    function computeGuardHashWithRealm(checkToStr, checkExec, hashSource = true, fWin = null, skipSharedCore = false) {
      const guardErr = checkGuardIdentityFast();
      if (guardErr) return guardErr;
      if (!verifyAllIntrinsicsWithRealm(checkToStr, checkExec, _docCreateElement, _nodeAppendChild, _iframeCwGet, fWin, skipSharedCore)) {
        return "TAMPERED_GUARD";
      }
      return finalizeGuardHashWithRealm(checkToStr, checkExec, hashSource, fWin);
    }

    function computeRuntimeGuardHash(forceFresh = true) {
      let realm = null;
      try {
        const guardErr = checkGuardIdentityFast();
        if (guardErr) return guardErr;
        // Reuse startup verification computed inside embedded VeilBreak's single iframe (eliminates duplicate iframe on cold unified handshake!)
        if (!forceFresh && _startupRealmGuardHash !== null && _startupRealmTs >= 0 && (monoNow() - _startupRealmTs) < 5_000) {
          if (_startupRealmGuardHash === "TAMPERED_GUARD" || _startupRealmGuardHash === "TAMPERED_SUBTLE") return _startupRealmGuardHash;
          const subtleErr = checkSubtleIdentityFast();
          if (subtleErr) return subtleErr;
          return _startupRealmGuardHash;
        }
        const needSourceHash = forceFresh || REQUIRE_GUARD_INTEGRITY;
        let checkToStr = _fnToString;
        let checkExec = _regexExec;
        let realmWin = null;
        if (typeof document !== "undefined") {
          realm = openVerifiedFreshRealm();
          if (!realm.ok) {
            return "TAMPERED_GUARD";
          }
          checkToStr = realm.fToStr;
          checkExec = realm.fExec;
          realmWin = realm.win;
        }
        const resHash = finalizeGuardHashWithRealm(checkToStr, checkExec, needSourceHash, realmWin);
        if (!forceFresh && resHash && resHash !== "TAMPERED_GUARD" && resHash !== "TAMPERED_SUBTLE") {
          _startupRealmGuardHash = resHash;
          _startupRealmTs = monoNow();
        }
        return resHash;
      } catch (_) {
        return "TAMPERED_GUARD";
      } finally {
        if (realm && realm.cleanup) realm.cleanup();
      }
    }

    function copyNullProtoProof(raw) {
      if (!raw || typeof raw !== "object") return null;
      const out = _objCreate(null);
      out.v = raw.v;
      out.ch = raw.ch;
      out.s = raw.s;
      out.f = raw.f;
      out.p = raw.p;
      out.cdp = raw.cdp;
      out.wr = raw.wr;
      out.wk = raw.wk;
      out.ms = raw.ms;
      out.d = raw.d;
      return out;
    }

    async function collectVeilBreakProof(challenge) {
      const invokeVb = async (vb) => {
        assertPromiseIntegrity();
        const rawP = vb.collectHandshakeProof(challenge);
        let resVal;
        if (rawP && rawP instanceof _NativePromise) {
          const box = await unwrapNativePromise(rawP);
          resVal = box ? box.v : null;
        } else if (rawP && typeof rawP === "object" && !("then" in rawP)) {
          resVal = rawP;
        } else {
          const box = await unwrapNativePromise(rawP);
          resVal = box ? box.v : null;
        }
        assertPromiseIntegrity();
        return copyNullProtoProof(resVal);
      };
      const vb0 = getTrustedVeilBreak();
      if (vb0 && typeof vb0.collectHandshakeProof === "function") {
        try { return await invokeVb(vb0); } catch (_) { return null; }
      }
      if (!REQUIRE_VB) return null;
      if (!EMBEDDED_VB && VB_TAMPER_SYM && _reflectApply(_hasOwn, window, [VB_TAMPER_SYM])) return null;
      const deadline = monoNow() + 4000;
      while (monoNow() < deadline) {
        if (!EMBEDDED_VB && VB_TAMPER_SYM && _reflectApply(_hasOwn, window, [VB_TAMPER_SYM])) return null;
        const vb = getTrustedVeilBreak();
        if (vb && typeof vb.collectHandshakeProof === "function") {
          try { return await invokeVb(vb); } catch (_) { return null; }
        }
        await new _NativePromise((r) => setTimeout(r, 25));
      }
      return null;
    }

    function hexNib(c) {
      if (c >= 48 && c <= 57) return c - 48;
      if (c >= 65 && c <= 70) return c - 55;
      if (c >= 97 && c <= 102) return c - 87;
      return -1;
    }
    function hexByte(s, idx) {
      return (hexNib(s.charCodeAt(idx + 1)) << 4) | hexNib(s.charCodeAt(idx + 2));
    }
    function decodePercentSafe(s) {
      if (s.indexOf("%") < 0) return s;
      return s.replace(/(?:%[0-9a-fA-F]{2})+/g, (run) => {
        let out = "";
        let i = 0;
        const len = run.length;
        while (i < len) {
          const b = hexByte(run, i);
          if (b === 0) { out += "\\0"; i += 3; continue; }
          if (b <= 0x7f) { out += String.fromCharCode(b); i += 3; continue; }
          if (b >= 0xc2 && b <= 0xdf && i + 6 <= len) {
            const b2 = hexByte(run, i + 3);
            if ((b2 & 0xc0) === 0x80) { out += String.fromCharCode(((b & 0x1f) << 6) | (b2 & 0x3f)); i += 6; continue; }
          } else if (b >= 0xe0 && b <= 0xef && i + 9 <= len) {
            const b2 = hexByte(run, i + 3);
            const b3 = hexByte(run, i + 6);
            const ok2 = b === 0xe0 ? (b2 >= 0xa0 && b2 <= 0xbf) : b === 0xed ? (b2 >= 0x80 && b2 <= 0x9f) : ((b2 & 0xc0) === 0x80);
            if (ok2 && (b3 & 0xc0) === 0x80) { out += String.fromCharCode(((b & 0x0f) << 12) | ((b2 & 0x3f) << 6) | (b3 & 0x3f)); i += 9; continue; }
          } else if (b >= 0xf0 && b <= 0xf4 && i + 12 <= len) {
            const b2 = hexByte(run, i + 3);
            const b3 = hexByte(run, i + 6);
            const b4 = hexByte(run, i + 9);
            const ok2 = b === 0xf0 ? (b2 >= 0x90 && b2 <= 0xbf) : b === 0xf4 ? (b2 >= 0x80 && b2 <= 0x8f) : ((b2 & 0xc0) === 0x80);
            if (ok2 && (b3 & 0xc0) === 0x80 && (b4 & 0xc0) === 0x80) {
              out += String.fromCodePoint(((b & 0x07) << 18) | ((b2 & 0x3f) << 12) | ((b3 & 0x3f) << 6) | (b4 & 0x3f));
              i += 12;
              continue;
            }
          }
          out += run.slice(i, i + 3);
          i += 3;
        }
        return out;
      });
    }

    function normalizeClientPath(raw) {
      const rawStr = _String(raw || "/");
      const qIdx = _reflectApply(_strIndexOf, rawStr, ["?"]);
      let s = qIdx >= 0 ? _reflectApply(_strSlice, rawStr, [0, qIdx]) : rawStr;
      for (let pass = 0; pass < 2; pass++) {
        const next = decodePercentSafe(s);
        if (next === s) break;
        s = next;
      }
      s = s.replace(/\\0/g, "").replace(/\\\\/g, "/");
      if (!_reflectApply(_strStartsWith, s, ["/"])) s = "/" + s;
      const rawSegs = splitByChar(s, "/");
      const stack = _objCreate(null);
      let stackLen = 0;
      for (let i = 0; i < rawSegs.length; i++) {
        const segRaw = rawSegs[i];
        const scIdx = _reflectApply(_strIndexOf, segRaw, [";"]);
        const seg = scIdx >= 0 ? _reflectApply(_strSlice, segRaw, [0, scIdx]) : segRaw;
        if (!seg || seg === ".") continue;
        if (seg === "..") { if (stackLen > 0) stackLen -= 1; }
        else stack[stackLen++] = seg;
      }
      let joined = "/";
      for (let i = 0; i < stackLen; i++) {
        if (i > 0) joined += "/";
        joined += stack[i];
      }
      return joined;
    }

    const BASE_SLASH = BASE + "/";
    function isGuardControlPath(pathname) {
      const raw = _String(pathname || "/");
      if (
        !_reflectApply(_strStartsWith, raw, [BASE_SLASH]) &&
        _reflectApply(_strIndexOf, raw, ["%"]) < 0 &&
        _reflectApply(_strIndexOf, raw, [".."]) < 0 &&
        _reflectApply(_strIndexOf, raw, ["\\\\"]) < 0 &&
        _reflectApply(_strIndexOf, raw, ["//"]) < 0 &&
        _reflectApply(_strIndexOf, raw, ["/."]) < 0 &&
        _reflectApply(_strIndexOf, raw, [";"]) < 0
      ) {
        return false;
      }
      const norm = normalizeClientPath(raw);
      return (
        norm === BASE + "/handshake" ||
        norm === BASE + "/boot" ||
        norm === BASE + "/guard.js" ||
        norm === BASE + "/health"
      );
    }

    const _CLEAN_CLIENT_PATH_RE = /^\\/(?:[A-Za-z0-9_~:@!$&'()*+,=-]+(?:\\.[A-Za-z0-9_~:@!$&'()*+,=-]+)*(?:\\/[A-Za-z0-9_~:@!$&'()*+,=-]+(?:\\.[A-Za-z0-9_~:@!$&'()*+,=-]+)*)*)?\\/?$/;
    function matchClientRules(cand) {
      const lower = _reflectApply(_strToLower, cand, []);
      for (let i = 0; i < RULES.length; i++) {
        const rule = RULES[i];
        if (rule instanceof RegExp) {
          rule.lastIndex = 0;
          if (_reflectApply(_regexExec, rule, [cand]) !== null) return true;
        } else if (
          rule === "*" ||
          rule === "/" ||
          lower === rule ||
          _reflectApply(_strStartsWith, lower, [_reflectApply(_strEndsWith, rule, ["/"]) ? rule : rule + "/"])
        ) {
          return true;
        }
      }
      return false;
    }

    function isProtectedPath(pathname) {
      const rawFull = String(pathname || "/");
      const qRaw = _reflectApply(_strIndexOf, rawFull, ["?"]);
      const raw = qRaw >= 0 ? _reflectApply(_strSlice, rawFull, [0, qRaw]) : rawFull;
      if (rxTest(_CLEAN_CLIENT_PATH_RE, raw)) {
        const clean = raw.length > 1 && raw[raw.length - 1] === "/" ? _reflectApply(_strSlice, raw, [0, -1]) : (raw || "/");
        return matchClientRules(clean);
      }
      const candidates = new Set([normalizeClientPath(raw)]);
      let dec = raw;
      for (let pass = 0; pass < 2; pass++) {
        const next = decodePercentSafe(dec);
        if (next === dec) break;
        dec = next;
      }
      if (dec !== raw) candidates.add(normalizeClientPath(dec));
      const q = _reflectApply(_strIndexOf, dec, ["?"]);
      if (q >= 0) candidates.add(normalizeClientPath(_reflectApply(_strSlice, dec, [0, q])));
      const h = _reflectApply(_strIndexOf, dec, ["#"]);
      if (h >= 0) candidates.add(normalizeClientPath(_reflectApply(_strSlice, dec, [0, h])));

      for (const cand of candidates) {
        if (matchClientRules(cand)) return true;
      }
      return false;
    }

    function assertSecureWebCrypto() {
      if (!_subtle) {
        throw new Error("PROXYSNARE_REQUIRES_SECURE_CONTEXT: WebCrypto (crypto.subtle) requires HTTPS or localhost.");
      }
    }

    function baseHref() {
      return (typeof document !== "undefined" && document.baseURI) || window.location.href;
    }

    function resolveInputUrl(input) {
      const b = baseHref();
      if (typeof input === "string") return new _URL(input, b);
      if (input instanceof _URL) return new _URL(input.href, b);
      if (input && typeof input.url === "string") return new _URL(input.url, b);
      return new _URL(String(input), b);
    }

    async function acquireBootChallenge() {
      assertPromiseIntegrity();
      if (pendingBoot && pendingBoot.bootToken && (!pendingBoot.exp || pendingBoot.exp > _dateNow() + 2000)) {
        const b = pendingBoot;
        pendingBoot = null;
        const out = _objCreate(null);
        out.boot = b;
        out.fromStamped = true;
        return out;
      }
      pendingBoot = null;
      if (!origFetch) throw new _Error("PROXYSNARE_FETCH_UNAVAILABLE");
      const bootInit = _objCreate(null);
      bootInit.method = "GET";
      bootInit.credentials = "same-origin";
      bootInit.cache = "no-store";
      const resp = (await unwrapNativePromise(origFetch(BASE + "/boot", bootInit))).v;
      const bootStatus = readRespStatus(resp);
      if (!(bootStatus >= 200 && bootStatus < 300)) throw new _Error("PROXYSNARE_BOOT_FAILED_" + bootStatus);
      const bootJsonObj = _ResponseJson
        ? (await unwrapNativePromise(_reflectApply(_ResponseJson, resp, []))).v
        : (await unwrapNativePromise(resp.json())).v;
      const out = _objCreate(null);
      out.boot = bootJsonObj;
      out.fromStamped = false;
      return out;
    }

    async function ensureSession(forceNew = false) {
      assertSecureWebCrypto();
      assertPromiseIntegrity();
      if (!origFetch) throw new _Error("PROXYSNARE_FETCH_UNAVAILABLE");
      if (state && !forceNew) return true;
      if (forceNew) {
        sessionGen += 1;
        state = null;
        initPromise = null;
      }
      if (initPromise) {
        await unwrapNativePromise(initPromise);
        return true;
      }
      const myGen = sessionGen;
      const p = (async () => {
        let bootRes = await acquireBootChallenge();
        let boot = bootRes.boot;
        const fromStamped = bootRes.fromStamped;
        assertPromiseIntegrity();
        if (FAIL_CLOSED_ON_TAMPER && checkSubtleIdentityFast()) {
          throw new _Error("PROXYSNARE_GUARD_TAMPERED");
        }
        const kp = (await unwrapNativePromise(_reflectApply(_capturedSubtle.generateKey, _subtle, [
          { name: "ECDH", namedCurve: "P-256" },
          false,
          ["deriveBits"],
        ]))).v;
        const clientPubRaw = new _Uint8Array((await unwrapNativePromise(_reflectApply(_capturedSubtle.exportKey, _subtle, ["raw", kp.publicKey]))).v);
        const clientPubB64 = toBase64(clientPubRaw);
        let guardHash = null;

        const postHandshake = async (activeBoot) => {
          const powNonce = solvePow(activeBoot.challenge, activeBoot.difficulty || 0);
          const browserProof = await collectVeilBreakProof(activeBoot.challenge || "");
          // Compute guardHash AFTER collectVeilBreakProof so cold unified boot reuses embedded VeilBreak's single startup iframe!
          if (guardHash === null) guardHash = computeRuntimeGuardHash(forceNew);
          // Reuse embedded VeilBreak's fresh CDP/automation scan synced via __PS_SYNC_CDP__ instead of running 3-4 redundant scans on cold unified boot!
          const trustedEmbeddedCdp = Boolean(EMBEDDED_VB && _privateVbApi && _privateVbApi.antiCdp && browserProof && (browserProof.cdp === 0 || browserProof.cdp === 1));
          const skipHandshakeCdp = Boolean(EMBEDDED_VB && _privateVbApi && _privateVbApi.antiCdp === false && !BLOCK_CDP_ACTIVE);
          const nowHs = monoNow();
          const cdpSyncedFresh = trustedEmbeddedCdp && cachedCdp.ts >= 0 && nowHs >= cachedCdp.ts && (nowHs - cachedCdp.ts) < 250;
          let psAutoActive = false;
          try {
            const needFullHsScan = !trustedEmbeddedCdp && (lastFullScanTs < 0 || (nowHs - lastFullScanTs) >= 30_000);
            if (needFullHsScan) lastFullScanTs = nowHs;
            if (Boolean(navigator && navigator.webdriver) || hasAutomationGlobals(needFullHsScan)) psAutoActive = true;
          } catch (_) {}
          let cdpActive = Boolean((browserProof && browserProof.cdp === 1) || psAutoActive || (!ALLOW_DEVTOOLS && cdpEverDetected));
          if (!cdpActive && !skipHandshakeCdp && !cdpSyncedFresh) {
            if (!trustedEmbeddedCdp || Boolean(_consoleDebug)) {
              cdpActive = detectCdpActive({ skipCache: true, allowFullScan: false, respectIframeThrottle: Boolean(trustedEmbeddedCdp) });
            }
          }
          if (cdpActive) cdpEverDetected = true;
          cachedCdp = { ts: monoNow(), active: cdpActive || (!ALLOW_DEVTOOLS && cdpEverDetected) };
          const hsBind = sha256HexSync(
            guardHash + "|" + (cdpActive ? "1" : "0") + "|" + ((browserProof && typeof browserProof.d === "string") ? browserProof.d : "")
          );
          const t0 = _dateNow();
          const hsPayload = _objCreate(null);
          hsPayload.protocol = "PS_ECDH_V2";
          hsPayload.clientPubB64 = clientPubB64;
          hsPayload.bootToken = activeBoot.bootToken;
          hsPayload.powNonce = powNonce;
          hsPayload.guardHash = guardHash;
          hsPayload.cdpActive = cdpActive;
          if (browserProof) hsPayload.browserProof = browserProof;
          hsPayload.t = t0;
          const hsHdrs = _objCreate(null);
          hsHdrs["Content-Type"] = "application/json";
          const hsInit = _objCreate(null);
          hsInit.method = "POST";
          hsInit.credentials = "same-origin";
          hsInit.cache = "no-store";
          hsInit.headers = hsHdrs;
          hsInit.body = _reflectApply(_jsonStringify, JSON, [hsPayload]);
          const resp = (await unwrapNativePromise(origFetch(BASE + "/handshake", hsInit))).v;
          const resObj = _objCreate(null);
          resObj.resp = resp;
          resObj.hsBind = hsBind;
          resObj.t0 = t0;
          resObj.t1 = _dateNow();
          return resObj;
        };

        let { resp, hsBind, t0, t1 } = await postHandshake(boot);
        if (readRespStatus(resp) === 403) {
          let errJson = null;
          const errCt = _reflectApply(_strToLower, _String(readHdr(readRespHeaders(resp), "content-type") || ""), []);
          if (_reflectApply(_strIncludes, errCt, ["json"])) {
            try { errJson = (await unwrapNativePromise(readRespCloneJson(resp))).v; } catch (_) {}
          }
          const errCode = errJson && typeof errJson.error === "string" ? errJson.error : "";
          // Allow single 1x retry on mobile IP roam / Happy Eyeballs flip (BOOT_TOKEN_IP_MISMATCH) or expiry even when !fromStamped!
          const shouldRetryBoot =
            errCode === "BOOT_TOKEN_IP_MISMATCH" ||
            errCode === "BOOT_TOKEN_EXPIRED" ||
            (fromStamped && (!errCode || _reflectApply(_strStartsWith, errCode, ["BOOT_TOKEN_"])));
          if (shouldRetryBoot) {
            const fresh = await acquireBootChallenge();
            boot = fresh.boot;
            ({ resp, hsBind, t0, t1 } = await postHandshake(boot));
          }
        }
        const finalHsStatus = readRespStatus(resp);
        if (!(finalHsStatus >= 200 && finalHsStatus < 300)) throw new _Error("PROXYSNARE_HANDSHAKE_FAILED_" + finalHsStatus);
        // Client-side fail-closed defense: even if an active MITM rewrote guardHash in POST /handshake and returned 200,
        // NEVER feed kp.privateKey into hooked SubtleCrypto.deriveBits() or install session state!
        if (FAIL_CLOSED_ON_TAMPER && (guardHash === "TAMPERED_SUBTLE" || guardHash === "TAMPERED_GUARD")) {
          throw new _Error("PROXYSNARE_GUARD_TAMPERED");
        }
        // Re-verify Promise.prototype integrity AFTER /handshake network round-trip (closes TOCTOU window!)
        assertPromiseIntegrity();
        const data = _ResponseJson
          ? (await unwrapNativePromise(_reflectApply(_ResponseJson, resp, []))).v
          : (await unwrapNativePromise(resp.json())).v;
        const isCleanHsField = (v) => typeof v === "string" && v.length > 0 && _reflectApply(_strIndexOf, v, ["|"]) < 0;
        if (
          !data ||
          !isCleanHsField(data.serverPubB64) ||
          !isCleanHsField(data.saltB64) ||
          !isCleanHsField(data.sessionId) ||
          !isCleanHsField(data.canary) ||
          (data.serverNowMs !== undefined && (typeof data.serverNowMs !== "number" || !Number.isFinite(data.serverNowMs)))
        ) {
          throw new _Error("PROXYSNARE_HANDSHAKE_MALFORMED");
        }

        if (SERVER_ECDSA_PUB) {
          if (typeof data.serverSigB64 !== "string" || !data.serverSigB64) {
            throw new _Error("PROXYSNARE_MITM_ECDH_SUBSTITUTION");
          }
          const verifyKey = (await unwrapNativePromise(_reflectApply(_capturedSubtle.importKey, _subtle, [
            "raw",
            fromBase64(SERVER_ECDSA_PUB),
            { name: "ECDSA", namedCurve: "P-256" },
            false,
            ["verify"],
          ]))).v;
          const authTranscript =
            "PS_HS_AUTH_V1|" +
            data.sessionId + "|" +
            clientPubB64 + "|" +
            data.serverPubB64 + "|" +
            data.saltB64 + "|" +
            _String(boot.bootToken || "") + "|" +
            _String(data.serverNowMs ?? "") + "|" +
            _String(data.canary || "") + "|" +
            hsBind;
          const sigValid = (await unwrapNativePromise(_reflectApply(_capturedSubtle.verify, _subtle, [
            { name: "ECDSA", hash: "SHA-256" },
            verifyKey,
            fromBase64(data.serverSigB64),
            _encodeUtf8(authTranscript),
          ]))).v;
          if (!sigValid) {
            throw new _Error("PROXYSNARE_MITM_ECDH_SUBSTITUTION");
          }
        }

        // Seal the entire ECDH -> HKDF -> HMAC key derivation chain inside _nativePromiseThen (sharedBits & cryptoKey NEVER touch Promise.prototype.then / await!)
        const infoBytes = _encodeUtf8("PS_ECDH_V2|" + data.sessionId + "|" + clientPubB64 + "|" + data.serverPubB64 + "|" + hsBind);
        const saltBytes = fromBase64(data.saltB64);
        const serverPubBytes = fromBase64(data.serverPubB64);
        const keyBox = await new _NativePromise((resolveKey, rejectKey) => {
          try {
            assertPromiseIntegrity();
            const pPub = _reflectApply(_capturedSubtle.importKey, _subtle, ["raw", serverPubBytes, { name: "ECDH", namedCurve: "P-256" }, false, []]);
            assertPromiseIntegrity();
            _reflectApply(_nativePromiseThen, pPub, [
              (serverPubKey) => {
                try {
                  assertPromiseIntegrity();
                  const pBits = _reflectApply(_capturedSubtle.deriveBits, _subtle, [{ name: "ECDH", public: serverPubKey }, kp.privateKey, 256]);
                  assertPromiseIntegrity();
                  _reflectApply(_nativePromiseThen, pBits, [
                    (sharedBits) => {
                      try {
                        assertPromiseIntegrity();
                        const pHkdf = _reflectApply(_capturedSubtle.importKey, _subtle, ["raw", sharedBits, "HKDF", false, ["deriveKey"]]);
                        assertPromiseIntegrity();
                        _reflectApply(_nativePromiseThen, pHkdf, [
                          (hkdfKey) => {
                            try {
                              assertPromiseIntegrity();
                              const pHmac = _reflectApply(_capturedSubtle.deriveKey, _subtle, [
                                { name: "HKDF", hash: "SHA-256", salt: saltBytes, info: infoBytes },
                                hkdfKey,
                                { name: "HMAC", hash: "SHA-256", length: 256 },
                                false,
                                ["sign"],
                              ]);
                              assertPromiseIntegrity();
                              _reflectApply(_nativePromiseThen, pHmac, [
                                (hmacKey) => {
                                  try {
                                    assertPromiseIntegrity();
                                    const box = _objCreate(null);
                                    box.k = hmacKey;
                                    resolveKey(box);
                                  } catch (e) { rejectKey(e); }
                                },
                                rejectKey,
                              ]);
                            } catch (e) { rejectKey(e); }
                          },
                          rejectKey,
                        ]);
                      } catch (e) { rejectKey(e); }
                    },
                    rejectKey,
                  ]);
                } catch (e) { rejectKey(e); }
              },
              rejectKey,
            ]);
          } catch (e) {
            rejectKey(e);
          }
        });
        const cryptoKey = keyBox.k;

        if (typeof data.serverNowMs === "number" && Number.isFinite(data.serverNowMs)) {
          const midpoint = t0 + _MathMax(0, t1 - t0) / 2;
          clockOffsetMs = _MathRound(data.serverNowMs - midpoint);
        } else {
          clockOffsetMs = 0;
        }

        const nextState = _objCreate(null);
        nextState.sessionId = data.sessionId;
        nextState.cryptoKey = cryptoKey;
        nextState.canary = data.canary;
        if (myGen === sessionGen) {
          seq = 0;
          state = nextState;
        }
        return true;
      })();
      initPromise = p;
      try {
        await unwrapNativePromise(p);
        return true;
      } finally {
        if (initPromise === p) initPromise = null;
      }
    }

    async function signRequestFields(method, pathWithQuery, bodyBytes, consoleEvalFlag = 0, gestureAgeAtCall = null, interactionSnap = undefined, callMonoAtCall = null) {
      await ensureSession(false);
      const st = state;
      if (!st) throw new _Error("PROXYSNARE_SESSION_UNAVAILABLE");
      const bodyHash =
        bodyBytes.byteLength === 0
          ? _EMPTY_SHA256_HEX
          : toHex((await unwrapNativePromise(_reflectApply(_capturedSubtle.digest, _subtle, ["SHA-256", bodyBytes]))).v);
      seq += 1;
      const mySeq = seq;
      const ts = _MathMax(0, _MathRound(_dateNow() + clockOffsetMs));
      const nonceBytes = new _Uint8Array(12);
      if (_getRandomValues) _reflectApply(_getRandomValues, crypto, [nonceBytes]);
      else crypto.getRandomValues(nonceBytes);
      const nonce = toHex(nonceBytes);
      const canary = st.canary;
      const upperMethod = _reflectApply(_strToUpper, _String(method || "GET"), []);
      const ctx = buildRuntimeContextHeader(consoleEvalFlag, gestureAgeAtCall, upperMethod, interactionSnap, callMonoAtCall);
      const canonical =
        "PS2|" + upperMethod + "|" + pathWithQuery + "|" + bodyHash + "|" +
        mySeq + "|" + ts + "|" + nonce + "|" + canary + "|" + ctx;
      const sigBuf = (await unwrapNativePromise(_reflectApply(_capturedSubtle.sign, _subtle, ["HMAC", st.cryptoKey, _encodeUtf8(canonical)]))).v;
      const outHdrs = _objCreate(null);
      outHdrs["X-PS-Session"] = st.sessionId;
      outHdrs["X-PS-Seq"] = _String(mySeq);
      outHdrs["X-PS-Ts"] = _String(ts);
      outHdrs["X-PS-Nonce"] = nonce;
      outHdrs["X-PS-Canary"] = canary;
      outHdrs["X-PS-Ctx"] = ctx;
      outHdrs["X-PS-Proof"] = toHex(sigBuf);
      const out = _objCreate(null);
      out.sessionId = st.sessionId;
      out.seq = mySeq;
      out.headers = outHdrs;
      return out;
    }

    function snapshotBodySync(body) {
      if (body == null) return { sync: true, bytes: new _Uint8Array(0), contentType: null };
      if (typeof body === "string") return { sync: true, bytes: _encodeUtf8(body), contentType: "text/plain;charset=UTF-8" };
      if (_ArrayBuffer && body instanceof _ArrayBuffer) {
        const copy = new _Uint8Array(body.byteLength);
        copy.set(new _Uint8Array(body));
        return { sync: true, bytes: copy, contentType: null };
      }
      if (_ArrayBuffer && _ArrayBuffer.isView(body)) {
        const copy = new _Uint8Array(body.byteLength);
        copy.set(new _Uint8Array(body.buffer, body.byteOffset, body.byteLength));
        return { sync: true, bytes: copy, contentType: null };
      }
      if (body instanceof URLSearchParams) {
        return { sync: true, bytes: _encodeUtf8(body.toString()), contentType: "application/x-www-form-urlencoded;charset=UTF-8" };
      }
      if (_Document && body instanceof _Document) {
        const xml = new XMLSerializer().serializeToString(body);
        const isHtml = typeof HTMLDocument !== "undefined" && body instanceof HTMLDocument;
        return { sync: true, bytes: _encodeUtf8(xml), contentType: (isHtml ? "text/html" : "application/xml") + ";charset=UTF-8" };
      }
      return { sync: false, raw: body };
    }

    async function finalizeBody(snap) {
      const boxBody = (bytes, ct) => {
        const o = _objCreate(null);
        o.bytes = bytes;
        o.contentType = ct;
        return o;
      };
      if (snap.sync) return boxBody(snap.bytes, snap.contentType);
      const body = snap.raw;
      if (typeof Blob !== "undefined" && body instanceof Blob) {
        return boxBody(new _Uint8Array(await body.arrayBuffer()), body.type || null);
      }
      if ((typeof FormData !== "undefined" && body instanceof FormData) || (typeof ReadableStream !== "undefined" && body instanceof ReadableStream)) {
        const tmp = new _Response(body);
        const ct = readHdr(readRespHeaders(tmp), "content-type");
        const ab = _respArrayBuffer ? await _reflectApply(_respArrayBuffer, tmp, []) : await tmp.arrayBuffer();
        return boxBody(new _Uint8Array(ab), ct);
      }
      return boxBody(_encodeUtf8(body), "text/plain;charset=UTF-8");
    }

    function shouldRehandshake(resp, cloneBody) {
      if (!resp || readRespStatus(resp) !== 403) return false;
      if (readHdr(readRespHeaders(resp), "X-PS-Rehandshake") === "1") return true;
      return Boolean(
        cloneBody &&
        Array.isArray(cloneBody.reasons) &&
        cloneBody.reasons.includes("REPEATER_UNKNOWN_OR_EXPIRED_SESSION")
      );
    }

    function applyRotatedCanary(usedSessionId, usedSeq, rotated, ack, rehs, invalidRes) {
      if (!usedSessionId || !state || state.sessionId !== usedSessionId) return;
      if (rehs) {
        state = null;
        return;
      }
      if (rotated) {
        const expectedAck = usedSessionId.slice(0, 8) + ":" + String(usedSeq);
        // Ignore stale cached X-PS-Next-Canary headers whose ack doesn't match the exact (session, seq) sent!
        if (!ack || ack === expectedAck) {
          state.canary = rotated;
        }
      } else if (invalidRes) {
        state = null;
      }
    }

    function snapshotInteractionSync(method) {
      const upperM = _reflectApply(_strToUpper, _String(method || "GET"), []);
      if (upperM === "GET" || upperM === "HEAD") return null;
      try {
        const vb = getTrustedVeilBreak();
        return vb && typeof vb.getLastInteraction === "function" ? vb.getLastInteraction() : null;
      } catch (_) {
        return null;
      }
    }

    function proxySnareFetch(input, init) {
      const safeInit = init && typeof init === "object" ? init : {};
      let reqUrl;
      try {
        reqUrl = resolveInputUrl(input);
      } catch {
        return origFetch(input, init);
      }
      if (reqUrl.origin !== window.location.origin || isGuardControlPath(reqUrl.pathname) || !isProtectedPath(reqUrl.pathname)) {
        return origFetch(input, init);
      }

      const isRequestObj = typeof Request !== "undefined" && input instanceof Request;
      const method = _reflectApply(_strToUpper, _String(safeInit.method || (isRequestObj ? input.method : "GET") || "GET"), []);
      const consoleEvalFlag = captureConsoleEvalFlag();
      const callMono = monoNow();
      const gestureAgeAtCall =
        lastTrustedGestureMs >= 0 && callMono >= lastTrustedGestureMs
          ? _MathMax(0, _MathMin(999_999, _MathRound(callMono - lastTrustedGestureMs)))
          : -1;
      const interactionSnap = snapshotInteractionSync(method);
      const activeSignal = safeInit.signal !== undefined ? safeInit.signal : (isRequestObj ? input.signal : null);
      const hasExplicitBody = safeInit.body !== undefined;
      const eagerSnap = hasExplicitBody ? snapshotBodySync(safeInit.body) : null;

      return enqueueProtected(async () => {
        if (activeSignal && activeSignal.aborted) {
          throw activeSignal.reason || new DOMException("The operation was aborted.", "AbortError");
        }
        let bodyBytes;
        let inferredCt = null;
        if (method === "GET" || method === "HEAD") {
          bodyBytes = _EMPTY_U8;
        } else if (hasExplicitBody) {
          const fin = await finalizeBody(eagerSnap);
          bodyBytes = fin.bytes;
          inferredCt = fin.contentType;
        } else if (isRequestObj) {
          const ab = await input.clone().arrayBuffer();
          bodyBytes = new _Uint8Array(ab);
        } else {
          bodyBytes = _EMPTY_U8;
        }

        const requestedRedirect = safeInit.redirect || (isRequestObj ? input.redirect : "follow") || "follow";

        const sendOnce = async (targetUrl, targetMethod, targetBytes, targetCt, forceRehandshake, precheckedNeedsSign = null) => {
          if (forceRehandshake) {
            try {
              await ensureSession(true);
            } catch (hsErr) {
              if (!IS_MONITOR_MODE) throw hsErr;
            }
          }
          const mergedHeaders = new _Headers(
            safeInit.headers !== undefined ? safeInit.headers : (isRequestObj ? input.headers : undefined)
          );
          const hasCt = _hdrHas ? _reflectApply(_hdrHas, mergedHeaders, ["content-type"]) : mergedHeaders.has("content-type");
          if (targetCt && !hasCt) {
            if (_hdrSet) _reflectApply(_hdrSet, mergedHeaders, ["content-type", targetCt]);
            else mergedHeaders.set("content-type", targetCt);
          }
          const needsSign =
            precheckedNeedsSign !== null
              ? precheckedNeedsSign
              : (targetUrl.origin === window.location.origin &&
                 !isGuardControlPath(targetUrl.pathname) &&
                 isProtectedPath(targetUrl.pathname));

          let usedSessionId = null;
          let usedSeq = 0;
          let monitorFailOpen = false;
          if (needsSign) {
            if (activeSignal && activeSignal.aborted) {
              throw activeSignal.reason || new DOMException("The operation was aborted.", "AbortError");
            }
            try {
              const signed = await signRequestFields(targetMethod, targetUrl.pathname + targetUrl.search, targetBytes, consoleEvalFlag, gestureAgeAtCall, interactionSnap, callMono);
              usedSessionId = signed.sessionId;
              usedSeq = signed.seq;
              const sh = signed.headers;
              if (_hdrSet) {
                _reflectApply(_hdrSet, mergedHeaders, ["X-PS-Session", sh["X-PS-Session"]]);
                _reflectApply(_hdrSet, mergedHeaders, ["X-PS-Seq", sh["X-PS-Seq"]]);
                _reflectApply(_hdrSet, mergedHeaders, ["X-PS-Ts", sh["X-PS-Ts"]]);
                _reflectApply(_hdrSet, mergedHeaders, ["X-PS-Nonce", sh["X-PS-Nonce"]]);
                _reflectApply(_hdrSet, mergedHeaders, ["X-PS-Canary", sh["X-PS-Canary"]]);
                _reflectApply(_hdrSet, mergedHeaders, ["X-PS-Ctx", sh["X-PS-Ctx"]]);
                _reflectApply(_hdrSet, mergedHeaders, ["X-PS-Proof", sh["X-PS-Proof"]]);
              } else {
                mergedHeaders.set("X-PS-Session", sh["X-PS-Session"]);
                mergedHeaders.set("X-PS-Seq", sh["X-PS-Seq"]);
                mergedHeaders.set("X-PS-Ts", sh["X-PS-Ts"]);
                mergedHeaders.set("X-PS-Nonce", sh["X-PS-Nonce"]);
                mergedHeaders.set("X-PS-Canary", sh["X-PS-Canary"]);
                mergedHeaders.set("X-PS-Ctx", sh["X-PS-Ctx"]);
                mergedHeaders.set("X-PS-Proof", sh["X-PS-Proof"]);
              }
            } catch (signErr) {
              if (IS_MONITOR_MODE && !(activeSignal && activeSignal.aborted)) {
                monitorFailOpen = true;
              } else {
                throw signErr;
              }
            }
          }

          const baseOpts = isRequestObj
            ? {
                credentials: input.credentials,
                cache: input.cache,
                referrer: input.referrer,
                referrerPolicy: input.referrerPolicy,
                integrity: input.integrity,
                keepalive: input.keepalive,
                signal: input.signal,
                ...(input.mode && input.mode !== "navigate" ? { mode: input.mode } : {}),
              }
            : {};

          const nextInit = {
            ...baseOpts,
            ...safeInit,
            method: targetMethod,
            headers: mergedHeaders,
            redirect: requestedRedirect,
          };
          // Prevent browser HTTP cache from replaying stale X-PS-Next-Canary on signed protected GETs
          if (needsSign && !monitorFailOpen && safeInit.cache === undefined && (!isRequestObj || !input.cache || input.cache === "default")) {
            nextInit.cache = "no-store";
          }
          if (targetMethod !== "GET" && targetMethod !== "HEAD" && (targetBytes.byteLength > 0 || hasExplicitBody || isRequestObj)) {
            nextInit.body = targetBytes;
          } else {
            delete nextInit.body;
          }

          const canonicalTargetUrl = targetUrl.origin + targetUrl.pathname + targetUrl.search;
          // If signal aborted during cold handshake/signing before any wire bytes were sent, throw WITHOUT wiping freshly minted session state!
          if (activeSignal && activeSignal.aborted) {
            throw activeSignal.reason || new DOMException("The operation was aborted.", "AbortError");
          }
          let resp;
          try {
            resp = await origFetch(canonicalTargetUrl, nextInit);
          } catch (err) {
            if (usedSessionId && state && state.sessionId === usedSessionId) {
              state = null;
            }
            throw err;
          }
          const respHdrs = readRespHeaders(resp);
          const respStatus = readRespStatus(resp);
          const respRedirected = readRespRedirected(resp);
          const respType = readRespType(resp);
          const rotated = readHdr(respHdrs, "X-PS-Next-Canary");
          const ack = readHdr(respHdrs, "X-PS-Canary-Ack");
          const rehs = readHdr(respHdrs, "X-PS-Rehandshake") === "1";
          const missingCanaryDesync =
            Boolean(usedSessionId) &&
            !rotated &&
            (respStatus >= 500 || (respStatus !== 403 && respStatus !== 429 && !ack));
          applyRotatedCanary(
            usedSessionId,
            usedSeq,
            rotated,
            ack,
            rehs,
            respRedirected || respType === "opaqueredirect" || respStatus === 0 || missingCanaryDesync
          );
          return resp;
        };

        let resp = await sendOnce(reqUrl, method, bodyBytes, inferredCt, false, true);
        let didRehandshake = false;
        let didRedirect = false;
        while (readRespStatus(resp) === 403 && !(activeSignal && activeSignal.aborted)) {
          const respHdrs403 = readRespHeaders(resp);
          const hasNextCanary = Boolean(readHdr(respHdrs403, "X-PS-Next-Canary"));
          if (hasNextCanary) break;
          const rehsHdr = readHdr(respHdrs403, "X-PS-Rehandshake") === "1";
          const redirectGetHint = readHdr(respHdrs403, "X-PS-Redirect-Get") === "1";
          let cloneJson = null;
          if (!rehsHdr) {
            const respCt = _reflectApply(_strToLower, _String(readHdr(respHdrs403, "content-type") || ""), []);
            if (_reflectApply(_strIncludes, respCt, ["json"])) {
              try { cloneJson = await readRespCloneJson(resp); } catch (_) {}
            }
          }
          const isProxySnare403 =
            redirectGetHint || Boolean(cloneJson && cloneJson.error === "REPEATER_OR_PROXY_BLOCKED");
          const respFinalUrl = readRespUrl(resp);
          if (!didRehandshake && (rehsHdr || shouldRehandshake(resp, cloneJson))) {
            didRehandshake = true;
            resp = await sendOnce(reqUrl, method, bodyBytes, inferredCt, true, true);
            continue;
          }
          if (
            !didRedirect &&
            isProxySnare403 &&
            requestedRedirect === "follow" &&
            readRespRedirected(resp) &&
            respFinalUrl
          ) {
            didRedirect = true;
            try {
              const finalUrl = new _URL(respFinalUrl);
              if (finalUrl.origin === window.location.origin && !isGuardControlPath(finalUrl.pathname)) {
                const isMutatingOrig = method !== "GET" && method !== "HEAD";
                const preserveMutate = isMutatingOrig && !redirectGetHint;
                const retryMethod = preserveMutate ? method : (method === "HEAD" ? "HEAD" : "GET");
                const retryBytes = preserveMutate ? bodyBytes : new _Uint8Array(0);
                const retryCt = preserveMutate ? inferredCt : null;
                state = null;
                const finalProtected = isProtectedPath(finalUrl.pathname);
                resp = await sendOnce(finalUrl, retryMethod, retryBytes, retryCt, finalProtected, finalProtected);
                continue;
              }
            } catch (_) {}
          }
          break;
        }
        return resp;
      }, activeSignal);
    }

    if (origFetch) {
      window.fetch = proxySnareFetch;
    }

    // Transparently instrument async XMLHttpRequest (Axios, jQuery, Angular HttpClient) via isolated internal XHR
    // Releases reqChain at readyState === 2 (HEADERS_RECEIVED) on non-403 responses so slow downloads never freeze SPA!
    const xhrMeta = new WeakMap();

    function clearShadowedXhrProps(xhr) {
      for (const p of ["readyState", "status", "statusText", "responseText", "response", "responseXML", "responseURL", "getResponseHeader", "getAllResponseHeaders"]) {
        try { delete xhr[p]; } catch (_) {}
      }
    }

    function failXhrCleanly(xhr, statusCode = 0, eventName = "error") {
      if (origAbort) { try { origAbort.call(xhr); } catch (_) {} }
      try {
        _defineProperty(xhr, "readyState", { value: 4, configurable: true });
        _defineProperty(xhr, "status", { value: statusCode, configurable: true });
      } catch (_) {}
      try { xhr.dispatchEvent(new Event("readystatechange")); } catch (_) {}
      if (typeof ProgressEvent !== "undefined") {
        try {
          xhr.dispatchEvent(new ProgressEvent(eventName));
          xhr.dispatchEvent(new ProgressEvent("loadend"));
        } catch (_) {}
      }
    }

    function mirrorXhrHeaders(target, inner) {
      const def = (k, v) => { try { _defineProperty(target, k, { value: v, configurable: true }); } catch (_) {} };
      def("status", inner.status);
      def("statusText", inner.statusText);
      def("responseURL", inner.responseURL);
      def("getResponseHeader", (name) => { try { return inner.getResponseHeader(name); } catch (_) { return null; } });
      def("getAllResponseHeaders", () => { try { return inner.getAllResponseHeaders(); } catch (_) { return ""; } });
    }

    function bindXhrBodyGetters(target, inner) {
      const defGet = (k, fn) => { try { _defineProperty(target, k, { get: fn, configurable: true }); } catch (_) {} };
      defGet("response", () => inner.response);
      if (!inner.responseType || inner.responseType === "text") {
        defGet("responseText", () => inner.responseText);
      }
      if (!inner.responseType || inner.responseType === "document") {
        defGet("responseXML", () => inner.responseXML);
      }
    }

    function mirrorXhrBody(target, inner) {
      const def = (k, v) => { try { _defineProperty(target, k, { value: v, configurable: true }); } catch (_) {} };
      try { def("response", inner.response); } catch (_) {}
      if (!inner.responseType || inner.responseType === "text") {
        try { def("responseText", inner.responseText); } catch (_) {}
      }
      if (!inner.responseType || inner.responseType === "document") {
        try { def("responseXML", inner.responseXML); } catch (_) {}
      }
    }

    function mirrorXhrToCaller(target, inner, opId) {
      mirrorXhrHeaders(target, inner);
      mirrorXhrBody(target, inner);
      try { _defineProperty(target, "readyState", { value: 4, configurable: true }); } catch (_) {}
      try { target.dispatchEvent(new Event("readystatechange")); } catch (_) {}
      if (xhrMeta.get(target)?.opId !== opId) return;
      if (typeof ProgressEvent !== "undefined") {
        try {
          target.dispatchEvent(new ProgressEvent("load"));
          if (xhrMeta.get(target)?.opId === opId) target.dispatchEvent(new ProgressEvent("loadend"));
        } catch (_) {}
      }
    }

    function settleXhrQueue(xhr) {
      const m = xhrMeta.get(xhr);
      if (m) {
        if (m.innerXhr) {
          try { origAbort.call(m.innerXhr); } catch (_) {}
          m.innerXhr = null;
        }
        if (m.inFlightSessionId) {
          if (state && state.sessionId === m.inFlightSessionId) state = null;
          m.inFlightSessionId = null;
        }
        if (m.releaseQueue) {
          const fn = m.releaseQueue;
          m.releaseQueue = null;
          fn();
        }
      }
    }

    function proxySnareXhrSend(body) {
      const meta = xhrMeta.get(this);
      if (!meta || !meta.url) return origSend.call(this, body);
      const reqUrl = meta.url;
      if (reqUrl.origin !== window.location.origin || isGuardControlPath(reqUrl.pathname) || !isProtectedPath(reqUrl.pathname)) {
        return origSend.call(this, body);
      }
      if (!meta.asyncFlag) {
        try { console.warn("[ProxySnare] Synchronous XMLHttpRequest to protected route cannot be signed asynchronously:", reqUrl.pathname); } catch (_) {}
        return origSend.call(this, body);
      }

      const consoleEvalFlag = captureConsoleEvalFlag();
      const callMono = monoNow();
      const gestureAgeAtCall =
        lastTrustedGestureMs >= 0 && callMono >= lastTrustedGestureMs
          ? _MathMax(0, _MathMin(999_999, _MathRound(callMono - lastTrustedGestureMs)))
          : -1;
      const interactionSnap = snapshotInteractionSync(meta.method);
      const opId = meta.opId;
      const self = this;
      const effectiveBody = (meta.method === "GET" || meta.method === "HEAD") ? null : body;
      const eagerSnap = snapshotBodySync(effectiveBody);
      meta.queued = true;

      _reflectApply(_nativePromiseThen, enqueueProtected(async () => {
        if (xhrMeta.get(self)?.opId !== opId) return;
        const { bytes: bodyBytes, contentType: inferredCt } = await finalizeBody(eagerSnap);
        if (xhrMeta.get(self)?.opId !== opId) return;

        const dispatchXhrAttempt = async (targetUrl, targetMethod, targetBytes, allowRehandshake, allowRedirect, forceRehandshake) => {
          const allowAnyRetry = allowRehandshake || allowRedirect;
          const needsSign =
            targetUrl.origin === window.location.origin &&
            !isGuardControlPath(targetUrl.pathname) &&
            isProtectedPath(targetUrl.pathname);
          let signed = null;
          if (needsSign) {
            try {
              if (forceRehandshake) await ensureSession(true);
              signed = await signRequestFields(targetMethod, targetUrl.pathname + targetUrl.search, targetBytes, consoleEvalFlag, gestureAgeAtCall, interactionSnap, callMono);
            } catch (signErr) {
              if (!IS_MONITOR_MODE) throw signErr;
            }
          }
          if (xhrMeta.get(self)?.opId !== opId) return;

          meta.queued = false;
          const inner = new OrigXHR();
          meta.innerXhr = inner;
          const canonicalXhrUrl = targetUrl.origin + targetUrl.pathname + targetUrl.search;
          if (meta.openArgs.length >= 5) {
            origOpen.call(inner, targetMethod, canonicalXhrUrl, true, meta.openArgs[3], meta.openArgs[4]);
          } else if (meta.openArgs.length >= 4) {
            origOpen.call(inner, targetMethod, canonicalXhrUrl, true, meta.openArgs[3]);
          } else {
            origOpen.call(inner, targetMethod, canonicalXhrUrl, true);
          }
          try { inner.withCredentials = self.withCredentials; } catch (_) {}
          try { if (self.responseType) inner.responseType = self.responseType; } catch (_) {}
          try { if (self.timeout) inner.timeout = self.timeout; } catch (_) {}
          try { if (meta.overrideMime && origOverrideMime) origOverrideMime.call(inner, meta.overrideMime); } catch (_) {}
          for (let i = 0; i < meta.headerEntries.length; i++) {
            const hk = meta.headerEntries[i][0];
            if (hk.toLowerCase().startsWith("x-ps-")) continue;
            try { origSetHdr.call(inner, hk, meta.headerEntries[i][1]); } catch (_) {}
          }
          if (inferredCt && !meta.headers["content-type"] && targetMethod !== "GET" && targetMethod !== "HEAD") {
            try { origSetHdr.call(inner, "Content-Type", inferredCt); } catch (_) {}
          }
          if (signed) {
            const sh = signed.headers;
            _reflectApply(origSetHdr, inner, ["X-PS-Session", sh["X-PS-Session"]]);
            _reflectApply(origSetHdr, inner, ["X-PS-Seq", sh["X-PS-Seq"]]);
            _reflectApply(origSetHdr, inner, ["X-PS-Ts", sh["X-PS-Ts"]]);
            _reflectApply(origSetHdr, inner, ["X-PS-Nonce", sh["X-PS-Nonce"]]);
            _reflectApply(origSetHdr, inner, ["X-PS-Canary", sh["X-PS-Canary"]]);
            _reflectApply(origSetHdr, inner, ["X-PS-Ctx", sh["X-PS-Ctx"]]);
            _reflectApply(origSetHdr, inner, ["X-PS-Proof", sh["X-PS-Proof"]]);
          }

          let headersMirrored = false;
          let bodyGettersBound = false;
          const ensureStreamMirrored = () => {
            if (!headersMirrored) { headersMirrored = true; mirrorXhrHeaders(self, inner); }
            if (!bodyGettersBound) { bodyGettersBound = true; bindXhrBodyGetters(self, inner); }
          };

          if (typeof ProgressEvent !== "undefined") {
            inner.onloadstart = (ev) => {
              if (xhrMeta.get(self)?.opId === opId) try { self.dispatchEvent(new ProgressEvent("loadstart", ev)); } catch (_) {}
            };
            inner.onprogress = (ev) => {
              if (xhrMeta.get(self)?.opId === opId && !(allowAnyRetry && inner.status === 403)) {
                // Mirror headers & bind lazy body getters ONCE (zero O(N^2) responseText flattening on streaming downloads!)
                ensureStreamMirrored();
                try { self.dispatchEvent(new ProgressEvent("progress", ev)); } catch (_) {}
              }
            };
            if (targetMethod !== "GET" && targetMethod !== "HEAD" && targetBytes.byteLength > 0 && inner.upload && self.upload) {
              for (const uEv of ["loadstart", "progress", "load", "loadend", "error", "abort", "timeout"]) {
                inner.upload.addEventListener(uEv, (ev) => {
                  if (xhrMeta.get(self)?.opId === opId) {
                    try { self.upload.dispatchEvent(new ProgressEvent(uEv, ev)); } catch (_) {}
                  }
                });
              }
            }
          }

          let xhrOutcomeKind = "done";
          let xhrRedirUrl = null;
          let xhrRedirMethod = "GET";
          let xhrRedirBytes = null;
          await new _NativePromise((done) => {
            let queueReleased = false;
            const releaseNow = (kind, rUrl = null, rMethod = "GET", rBytes = null) => {
              if (queueReleased) return;
              queueReleased = true;
              xhrOutcomeKind = kind;
              xhrRedirUrl = rUrl;
              xhrRedirMethod = rMethod;
              xhrRedirBytes = rBytes;
              meta.releaseQueue = null;
              done();
            };
            meta.releaseQueue = () => releaseNow("aborted");
            meta.inFlightSessionId = signed ? signed.sessionId : null;

            const expectedUrl = targetUrl.origin + targetUrl.pathname + targetUrl.search;
            let canaryHandled = false;
            let emittedRs2 = false;
            let emittedRs3 = false;
            inner.onreadystatechange = () => {
              if (xhrMeta.get(self)?.opId !== opId) return;
              const rs = readXhrReadyState(inner);
              const st = readXhrStatus(inner);
              if (rs >= 2 && !canaryHandled) {
                canaryHandled = true;
                meta.inFlightSessionId = null;
                let rehs = false;
                let redirGet = false;
                const respUrl = readXhrResponseUrl(inner);
                const rotHdr = readXhrRespHdr(inner, "X-PS-Next-Canary");
                if (signed) {
                  try {
                    const ack = readXhrRespHdr(inner, "X-PS-Canary-Ack");
                    rehs = readXhrRespHdr(inner, "X-PS-Rehandshake") === "1";
                    redirGet = readXhrRespHdr(inner, "X-PS-Redirect-Get") === "1";
                    const missingCanaryDesync =
                      !rotHdr && (st >= 500 || (st !== 403 && st !== 429 && !ack));
                    applyRotatedCanary(
                      signed.sessionId,
                      signed.seq,
                      rotHdr,
                      ack,
                      rehs,
                      st === 0 || missingCanaryDesync || redirGet || (!rotHdr && respUrl && respUrl !== expectedUrl)
                    );
                  } catch (_) {}
                }
                let deferredRedirectFinalUrl = null;
                if (st !== 403 && st !== 0) {
                  releaseNow("streaming");
                  if (!emittedRs2) {
                    emittedRs2 = true;
                    if (!headersMirrored) { headersMirrored = true; mirrorXhrHeaders(self, inner); }
                    try { _defineProperty(self, "readyState", { value: 2, configurable: true }); self.dispatchEvent(new Event("readystatechange")); } catch (_) {}
                  }
                } else if (allowRehandshake && st === 403 && rehs) {
                  try { origAbort.call(inner); } catch (_) {}
                  meta.innerXhr = null;
                  releaseNow("rehandshake");
                  return;
                } else if (
                  allowRedirect &&
                  st === 403 &&
                  !rotHdr &&
                  (redirGet || (respUrl && respUrl !== expectedUrl))
                ) {
                  try {
                    const finalUrl = new _URL(respUrl || expectedUrl, baseHref());
                    const respCtXhr = _reflectApply(_strToLower, _String(readXhrRespHdr(inner, "content-type") || ""), []);
                    const isJsonCt = _reflectApply(_strIncludes, respCtXhr, ["json"]);
                    const isPs403 =
                      redirGet ||
                      Boolean(readXhrRespHdr(inner, "X-ProxySnare-Mode")) ||
                      (isProtectedPath(finalUrl.pathname) && isJsonCt);
                    if (finalUrl.origin === window.location.origin && !isGuardControlPath(finalUrl.pathname)) {
                      if (isPs403) {
                        const isMutatingOrig = targetMethod !== "GET" && targetMethod !== "HEAD";
                        const preserveMutate = isMutatingOrig && !redirGet;
                        state = null;
                        try { origAbort.call(inner); } catch (_) {}
                        meta.innerXhr = null;
                        releaseNow(
                          "redirect",
                          finalUrl,
                          preserveMutate ? targetMethod : (targetMethod === "HEAD" ? "HEAD" : "GET"),
                          preserveMutate ? targetBytes : new _Uint8Array(0)
                        );
                        return;
                      } else if (isJsonCt) {
                        deferredRedirectFinalUrl = finalUrl;
                      }
                    }
                  } catch (_) {}
                }
                if (deferredRedirectFinalUrl) inner._psDeferRedir = deferredRedirectFinalUrl;
              }
              if (rs === 3 && st !== 403 && st !== 0 && !emittedRs3) {
                emittedRs3 = true;
                ensureStreamMirrored();
                try { _defineProperty(self, "readyState", { value: 3, configurable: true }); self.dispatchEvent(new Event("readystatechange")); } catch (_) {}
              }
            };
            // Completion mirroring exclusively in onload (NEVER in onreadystatechange(4), so network errors/timeouts never falsely fire 'load'!)
            inner.onload = () => {
              meta.inFlightSessionId = null;
              meta.innerXhr = null;
              if (allowRedirect && inner._psDeferRedir && readXhrStatus(inner) === 403) {
                let matchedPs403 = false;
                try {
                  if (inner.responseType === "json") matchedPs403 = Boolean(inner.response && inner.response.error === "REPEATER_OR_PROXY_BLOCKED");
                  else if (!inner.responseType || inner.responseType === "text") matchedPs403 = typeof inner.responseText === "string" && _reflectApply(_strIncludes, inner.responseText, ['"REPEATER_OR_PROXY_BLOCKED"']);
                } catch (_) {}
                if (matchedPs403) {
                  const isMutatingOrig = targetMethod !== "GET" && targetMethod !== "HEAD";
                  state = null;
                  releaseNow("redirect", inner._psDeferRedir, isMutatingOrig ? targetMethod : (targetMethod === "HEAD" ? "HEAD" : "GET"), isMutatingOrig ? targetBytes : new _Uint8Array(0));
                  return;
                }
              }
              releaseNow("done");
              if (xhrMeta.get(self)?.opId === opId) {
                mirrorXhrToCaller(self, inner, opId);
              }
            };
            inner.onerror = () => {
              meta.inFlightSessionId = null;
              meta.innerXhr = null;
              if (!canaryHandled && signed && state && state.sessionId === signed.sessionId) state = null;
              releaseNow("error");
              if (xhrMeta.get(self)?.opId === opId) failXhrCleanly(self, 0, "error");
            };
            inner.ontimeout = () => {
              meta.inFlightSessionId = null;
              meta.innerXhr = null;
              if (!canaryHandled && signed && state && state.sessionId === signed.sessionId) state = null;
              releaseNow("timeout");
              if (xhrMeta.get(self)?.opId === opId) failXhrCleanly(self, 0, "timeout");
            };
            origSend.call(inner, targetMethod !== "GET" && targetMethod !== "HEAD" && effectiveBody != null ? targetBytes : null);
          });

          if (xhrMeta.get(self)?.opId !== opId) return;
          if (xhrOutcomeKind === "rehandshake") {
            await dispatchXhrAttempt(targetUrl, targetMethod, targetBytes, false, allowRedirect, true);
          } else if (xhrOutcomeKind === "redirect" && xhrRedirUrl) {
            await dispatchXhrAttempt(xhrRedirUrl, xhrRedirMethod || "GET", xhrRedirBytes || new _Uint8Array(0), false, false, isProtectedPath(xhrRedirUrl.pathname));
          }
        };

        await dispatchXhrAttempt(reqUrl, meta.method, bodyBytes, true, true, false);
      }), [undefined, (err) => {
        meta.queued = false;
        if (xhrMeta.get(self)?.opId === opId) settleXhrQueue(self);
        if (IS_MONITOR_MODE && xhrMeta.get(self)?.opId === opId) {
          try { origSend.call(self, body); return; } catch (_) {}
        }
        try { console.error("[ProxySnare] Failed to sign XMLHttpRequest:", err); } catch (_) {}
        if (xhrMeta.get(self)?.opId === opId) {
          failXhrCleanly(self, 0, "error");
        }
      }]);
    }

    if (hasXhr) {
      XMLHttpRequest.prototype.open = function proxySnareXhrOpen(method, url, asyncFlag = true) {
        clearShadowedXhrProps(this);
        settleXhrQueue(this);
        const prev = xhrMeta.get(this);
        const opId = (prev ? prev.opId : 0) + 1;
        let resolvedUrl = null;
        try { resolvedUrl = new _URL(String(url || ""), baseHref()); } catch (_) {}
        xhrMeta.set(this, {
          opId,
          openArgs: Array.prototype.slice.call(arguments),
          headerEntries: [],
          headers: Object.create(null),
          overrideMime: "",
          method: String(method || "GET").toUpperCase(),
          url: resolvedUrl,
          asyncFlag: Boolean(asyncFlag),
          queued: false,
          inFlightSessionId: null,
          innerXhr: null,
          releaseQueue: null,
        });
        return origOpen.apply(this, arguments);
      };

      XMLHttpRequest.prototype.setRequestHeader = function proxySnareXhrSetHdr(name, val) {
        const m = xhrMeta.get(this);
        if (m) {
          m.headers[String(name).toLowerCase()] = true;
          m.headerEntries.push([String(name), String(val)]);
        }
        return origSetHdr.call(this, name, val);
      };

      if (origOverrideMime) {
        XMLHttpRequest.prototype.overrideMimeType = function proxySnareXhrOverrideMime(mime) {
          const m = xhrMeta.get(this);
          if (m) m.overrideMime = String(mime || "");
          return origOverrideMime.call(this, mime);
        };
      }

      XMLHttpRequest.prototype.abort = function proxySnareXhrAbort() {
        clearShadowedXhrProps(this);
        const m = xhrMeta.get(this);
        const wasActive = Boolean(m && (m.queued || m.innerXhr));
        if (m) {
          m.opId += 1;
          m.queued = false;
        }
        settleXhrQueue(this);
        const res = origAbort.call(this);
        if (wasActive && typeof ProgressEvent !== "undefined") {
          try {
            this.dispatchEvent(new ProgressEvent("abort"));
            this.dispatchEvent(new ProgressEvent("loadend"));
          } catch (_) {}
        }
        return res;
      };

      XMLHttpRequest.prototype.send = proxySnareXhrSend;
    }

    const psApi = Object.freeze({
      // Never expose internal session state, HMAC CryptoKey, sessionId, or rotating canary!
      ready: () => enqueueProtected(() => _reflectApply(_nativePromiseThen, ensureSession(false), [() => true])),
      detectCdpActive: () => detectCdpActive(true),
      guardHash: () => computeRuntimeGuardHash(true),
      version: VERSION,
    });
    try {
      _defData(window, "ProxySnare", psApi, false, false, true);
    } catch (_) {}
  }/*__PS_GUARD_MAIN_END__*/
  __psGuardMain(INITIAL_BOOT_INLINE);
})();
`);
}

module.exports = { buildBrowserGuardScript, computeGuardIntegrity };
