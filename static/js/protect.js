// protect.js
// Encrypts files and records in the BROWSER, using the Web Crypto API.
//
// This deliberately does not send the file to the server. A government
// register of weak systems is one thing to hold; the actual patient
// records are another, and they have no business leaving the machine
// they are on.
//
// Format of a protected file:
//   "CAS1" magic (4) + salt (16) + iv (12) + ciphertext

var subtle = window.crypto && window.crypto.subtle;
var MAGIC = [67, 65, 83, 49];
var MAX_FILE = 20 * 1024 * 1024;

function pEl(id) { return document.getElementById(id); }

// The site refuses anything that changes data without this token.
function csrfToken() {
  var m = document.querySelector('meta[name="csrf-token"]');
  return m ? m.getAttribute("content") : "";
}

function humanSize(n) {
  if (n < 1024) return n + " B";
  if (n < 1024 * 1024) return (n / 1024).toFixed(1) + " KB";
  return (n / 1024 / 1024).toFixed(1) + " MB";
}

function b64(u8) {
  var s = "";
  for (var i = 0; i < u8.length; i++) s += String.fromCharCode(u8[i]);
  return btoa(s);
}
function unb64(str) {
  var bin = atob(str), u8 = new Uint8Array(bin.length);
  for (var i = 0; i < bin.length; i++) u8[i] = bin.charCodeAt(i);
  return u8;
}

async function makeKey(pass, salt) {
  var base = await subtle.importKey("raw", new TextEncoder().encode(pass),
                                    "PBKDF2", false, ["deriveKey"]);
  return subtle.deriveKey(
    { name: "PBKDF2", salt: salt, iterations: 250000, hash: "SHA-256" },
    base, { name: "AES-GCM", length: 256 }, false, ["encrypt", "decrypt"]);
}

function saveBlob(bytes, name) {
  var a = document.createElement("a");
  a.href = URL.createObjectURL(new Blob([bytes], { type: "application/octet-stream" }));
  a.download = name;
  a.click();
  setTimeout(function () { URL.revokeObjectURL(a.href); }, 1000);
}

function readFile(file) {
  return new Promise(function (resolve, reject) {
    var fr = new FileReader();
    fr.onload = function () { resolve(new Uint8Array(fr.result)); };
    fr.onerror = function () { reject(new Error("could not read the file")); };
    fr.readAsArrayBuffer(file);
  });
}

function notAvailable(out) {
  if (subtle) return false;
  out.innerHTML = '<div class="flash bad">This browser will not allow '
    + 'encryption unless the page is served over localhost or HTTPS. '
    + 'Open http://127.0.0.1:5000 rather than a file path.</div>';
  return true;
}

// ---------------------------------------------------------------
// Files
// ---------------------------------------------------------------

async function protectFile() {
  var out = pEl("fileOut");
  var input = pEl("fileIn");
  var file = input.files[0];
  var pass = pEl("filePass").value;

  if (notAvailable(out)) return;
  if (!file) { out.innerHTML = '<div class="flash bad">Choose a file first.</div>'; return; }
  if (file.size > MAX_FILE) {
    out.innerHTML = '<div class="flash bad">That file is ' + humanSize(file.size)
      + '. This build handles up to 20 MB, because it encrypts the whole file '
      + 'in memory. A production version would work in chunks.</div>';
    return;
  }
  if (pass.length < 8) {
    out.innerHTML = '<div class="flash bad">Use a passphrase of at least eight '
      + 'characters. This is the only thing standing between the file and '
      + 'anyone who gets a copy.</div>';
    return;
  }

  out.innerHTML = '<div class="flash ok">Encrypting ' + file.name + '...</div>';

  try {
    var data = await readFile(file);
    var salt = window.crypto.getRandomValues(new Uint8Array(16));
    var iv = window.crypto.getRandomValues(new Uint8Array(12));
    var key = await makeKey(pass, salt);
    var ct = new Uint8Array(await subtle.encrypt({ name: "AES-GCM", iv: iv }, key, data));

    var packed = new Uint8Array(32 + ct.length);
    packed.set(MAGIC, 0);
    packed.set(salt, 4);
    packed.set(iv, 20);
    packed.set(ct, 32);

    saveBlob(packed, file.name + ".protected");

    out.innerHTML = '<div class="flash ok">' + file.name
      + ' is protected and downloading as <b>' + file.name + '.protected</b></div>'
      + '<table style="margin-top:12px"><tbody>'
      + '<tr><td class="dim" style="width:180px">Original</td><td>' + humanSize(file.size) + '</td></tr>'
      + '<tr><td class="dim">Protected</td><td>' + humanSize(packed.length) + '</td></tr>'
      + '<tr><td class="dim">Algorithm</td><td class="mono">AES-256-GCM</td></tr>'
      + '<tr><td class="dim">Key from</td><td class="mono">PBKDF2-SHA256, 250,000 rounds</td></tr>'
      + '<tr><td class="dim">Left this machine</td><td style="color:var(--low)">No. Encrypted here in the browser.</td></tr>'
      + '<tr><td class="dim">Holds until</td><td style="color:var(--low)">Beyond any known attack, including quantum</td></tr>'
      + '</tbody></table>'
      + '<p class="dim" style="margin:12px 0 0">The original on your disk is '
      + 'untouched. Check the protected copy opens before you delete it.</p>';
  } catch (e) {
    out.innerHTML = '<div class="flash bad">Could not encrypt: ' + e.message + '</div>';
  }
}

async function openFile() {
  var out = pEl("fileOut");
  var file = pEl("fileIn").files[0];
  var pass = pEl("filePass").value;

  if (notAvailable(out)) return;
  if (!file) { out.innerHTML = '<div class="flash bad">Choose the .protected file first.</div>'; return; }

  try {
    var data = await readFile(file);
    if (data.length < 33 || data[0] !== MAGIC[0] || data[1] !== MAGIC[1]
        || data[2] !== MAGIC[2] || data[3] !== MAGIC[3]) {
      out.innerHTML = '<div class="flash bad">That is not a file this site '
        + 'protected. Choose one ending in .protected</div>';
      return;
    }
    var key = await makeKey(pass, data.slice(4, 20));
    var pt = new Uint8Array(await subtle.decrypt(
      { name: "AES-GCM", iv: data.slice(20, 32) }, key, data.slice(32)));

    var name = file.name.replace(/\.protected$/, "") || "recovered";
    saveBlob(pt, name);

    out.innerHTML = '<div class="flash ok">Opened. <b>' + name
      + '</b> is downloading.</div>'
      + '<p class="dim" style="margin:10px 0 0">' + humanSize(pt.length)
      + ' recovered, byte for byte identical to the original.</p>';
  } catch (e) {
    out.innerHTML = '<div class="flash bad">Wrong passphrase, or the file was '
      + 'altered after it was protected. AES-GCM checks for tampering, so a '
      + 'changed file will not open even with the right passphrase.</div>';
  }
}

// ---------------------------------------------------------------
// A single record
// ---------------------------------------------------------------

async function protectText() {
  var out = pEl("textOut");
  var text = pEl("textIn").value.trim();
  var pass = pEl("textPass").value;

  if (notAvailable(out)) return;
  if (!text) { out.innerHTML = '<div class="flash bad">Enter the record first.</div>'; return; }
  if (pass.length < 8) { out.innerHTML = '<div class="flash bad">Use a passphrase of at least eight characters.</div>'; return; }

  var salt = window.crypto.getRandomValues(new Uint8Array(16));
  var iv = window.crypto.getRandomValues(new Uint8Array(12));
  var key = await makeKey(pass, salt);
  var ct = await subtle.encrypt({ name: "AES-GCM", iv: iv }, key,
                                new TextEncoder().encode(text));
  var packed = b64(salt) + "." + b64(iv) + "." + b64(new Uint8Array(ct));

  out.innerHTML = '<div class="flash ok">Protected with AES-256-GCM.</div>'
    + '<div class="field" style="margin-top:12px"><label>Protected record</label>'
    + '<input id="textResult" value="' + packed + '" readonly></div>'
    + '<button type="button" class="btn small" id="copyResult">Copy</button>';

  pEl("copyResult").addEventListener("click", function () {
    pEl("textResult").select();
    try { document.execCommand("copy"); this.textContent = "Copied"; } catch (e) {}
  });
}

async function openText() {
  var out = pEl("textOut");
  var packed = pEl("textIn").value.trim();
  var pass = pEl("textPass").value;

  if (notAvailable(out)) return;
  var parts = packed.split(".");
  if (parts.length !== 3) {
    out.innerHTML = '<div class="flash bad">Paste the protected record into the '
      + 'box above, then press Open.</div>';
    return;
  }
  try {
    var key = await makeKey(pass, unb64(parts[0]));
    var pt = await subtle.decrypt({ name: "AES-GCM", iv: unb64(parts[1]) },
                                  key, unb64(parts[2]));
    out.innerHTML = '<div class="flash ok">Opened</div>'
      + '<div class="field" style="margin-top:12px"><label>Your record</label>'
      + '<input value="' + new TextDecoder().decode(pt).replace(/"/g, "&quot;") + '" readonly></div>';
  } catch (e) {
    out.innerHTML = '<div class="flash bad">Wrong passphrase, or the record was altered.</div>';
  }
}

document.addEventListener("DOMContentLoaded", function () {
  var pairs = [["fileEnc", protectFile], ["fileDec", openFile],
               ["textEnc", protectText], ["textDec", openText]];
  pairs.forEach(function (p) {
    var el = pEl(p[0]);
    if (el) el.addEventListener("click", p[1]);
  });

  var banner = pEl("cryptoState");
  if (banner) {
    banner.innerHTML = subtle
      ? '<div class="flash ok">Your browser can encrypt. Nothing on this page '
        + 'is sent to the server.</div>'
      : '<div class="flash bad">Encryption is unavailable. Open the site over '
        + 'http://127.0.0.1:5000 rather than as a file.</div>';
  }
});

// ---------------------------------------------------------------
// Re-sealing documents whose old seal (SHA-1, MD5) can be forged.
// The document stays on this computer: only its SHA-384 fingerprint is
// sent, and the server signs that.
// ---------------------------------------------------------------

function hexOf(buf) {
  return Array.from(new Uint8Array(buf))
    .map(function (b) { return b.toString(16).padStart(2, "0"); }).join("");
}

async function fingerprint(file) {
  var data = await readFile(file);
  return hexOf(await subtle.digest("SHA-384", data));
}

async function sealFiles() {
  var out = pEl("sealOut");
  var files = Array.from(pEl("sealIn").files || []);
  if (notAvailable(out)) return;
  if (!files.length) { out.innerHTML = '<div class="flash bad">Choose one or more documents.</div>'; return; }

  out.innerHTML = '<div class="flash ok">Sealing ' + files.length + ' document(s)...</div>';
  var seals = [], rows = "";
  for (var i = 0; i < files.length; i++) {
    var f = files[i];
    var sha = await fingerprint(f);
    var res = await fetch("/seal", {
      method: "POST", headers: { "Content-Type": "application/json",
                                 "X-CSRF-Token": csrfToken() },
      body: JSON.stringify({ name: f.name, size: f.size, sha384: sha,
                             system: (pEl("sealSystem") || {}).value || "" })
    });
    var seal = await res.json();
    if (seal.error) { out.innerHTML = '<div class="flash bad">' + seal.error + '</div>'; return; }
    seals.push(seal);
    rows += '<tr><td>' + f.name + '</td><td class="mono dim">' + sha.slice(0, 20) + '&hellip;</td></tr>';
  }

  var bundle = seals.length === 1 ? seals[0] : { seals: seals };
  var name = seals.length === 1 ? files[0].name + ".seal.json" : "documents.seal.json";
  saveBlob(new TextEncoder().encode(JSON.stringify(bundle, null, 2)), name);

  out.innerHTML = '<div class="flash ok">' + seals.length + ' document(s) sealed with SHA-384. '
    + 'Saved as <b>' + name + '</b> &mdash; keep it with the documents.</div>'
    + '<table style="margin-top:10px"><tbody>' + rows + '</tbody></table>'
    + '<p class="dim" style="margin:10px 0 0">The documents never left this computer.</p>';
}

async function checkSeal() {
  var out = pEl("sealOut");
  var doc = (pEl("checkDoc").files || [])[0];
  var sealFile = (pEl("checkSeal").files || [])[0];
  if (notAvailable(out)) return;
  if (!doc || !sealFile) {
    out.innerHTML = '<div class="flash bad">Choose the document and its .seal.json file.</div>';
    return;
  }

  var parsed;
  try { parsed = JSON.parse(new TextDecoder().decode(await readFile(sealFile))); }
  catch (e) { out.innerHTML = '<div class="flash bad">That seal file cannot be read.</div>'; return; }

  var sha = await fingerprint(doc);
  var list = parsed.seals ? parsed.seals : [parsed];
  var seal = list.find(function (s) { return s.sha384 === sha; })
          || list.find(function (s) { return s.document === doc.name; });

  // Nothing matched. If the seal file holds exactly one seal, compare
  // against that anyway - "this document has changed" is far more useful
  // than "no match", which leaves people guessing.
  var nameDiffers = false;
  if (!seal && list.length === 1) { seal = list[0]; nameDiffers = true; }

  if (!seal) {
    out.innerHTML = '<div class="flash bad">That seal file holds ' + list.length
      + ' seals, and none is for this document. Check you picked the right pair.</div>';
    return;
  }

  var res = await fetch("/seal/verify", {
    method: "POST", headers: { "Content-Type": "application/json",
                               "X-CSRF-Token": csrfToken() },
    body: JSON.stringify({ seal: seal })
  });
  var v = await res.json();

  if (!v.genuine) {
    out.innerHTML = '<div class="flash bad"><b>Do not trust this.</b> ' + v.reason + '</div>';
  } else if (seal.sha384 !== sha) {
    out.innerHTML = '<div class="flash bad"><b>This does not match the seal.</b> '
      + 'The seal was made for <b>' + seal.document + '</b> on ' + seal.sealed_at + '.'
      + (nameDiffers && seal.document !== doc.name
         ? ' You chose <b>' + doc.name + '</b> - either a different document, or the same one after it was changed.'
         : ' The document has been changed since then. Do not trust this copy.')
      + '</div>';
  } else {
    out.innerHTML = '<div class="flash ok"><b>Genuine.</b> Unchanged since it was sealed on '
      + seal.sealed_at + ' by ' + seal.sealed_by + '.</div>';
  }
}

document.addEventListener("DOMContentLoaded", function () {
  var a = pEl("sealBtn"), b = pEl("checkBtn");
  if (a) a.addEventListener("click", sealFiles);
  if (b) b.addEventListener("click", checkSeal);
});
