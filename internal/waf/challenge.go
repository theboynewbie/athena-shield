package waf

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"html"
	"net/http"
	"strconv"
	"strings"
	"time"
)

const (
	ClearanceCookieName = "athena_clearance"
	ChallengeVerifyPath = "/__athena_challenge/verify"
	DefaultClearanceTTL = 30 * time.Minute
)

func uaHash(ua string) string {
	h := sha256.Sum256([]byte(ua))
	return hex.EncodeToString(h[:8])
}

func hasLeadingZeroBits(hash []byte, bits int) bool {
	if bits <= 0 {
		return true
	}
	fullBytes := bits / 8
	remBits := bits % 8
	if fullBytes >= len(hash) {
		return false
	}
	for i := 0; i < fullBytes; i++ {
		if hash[i] != 0 {
			return false
		}
	}
	if remBits > 0 {
		mask := byte(0xFF << (8 - remBits))
		if hash[fullBytes]&mask != 0 {
			return false
		}
	}
	return true
}

func (e *Engine) ChallengeDifficulty() int {
	snap := e.snap.Load()
	if snap != nil && snap.jsChallengeDifficulty >= 12 && snap.jsChallengeDifficulty <= 20 {
		return snap.jsChallengeDifficulty
	}
	return 14
}

func (e *Engine) signChallenge(msg string) string {
	mac := hmac.New(sha256.New, e.secret)
	mac.Write([]byte(msg))
	return hex.EncodeToString(mac.Sum(nil))
}

func (e *Engine) CreateChallenge(ip, ua string, difficulty int) (nonce string, expires int64, sig string) {
	buf := make([]byte, 16)
	_, _ = rand.Read(buf)
	nonce = hex.EncodeToString(buf)
	expires = time.Now().Unix() + 120
	msg := fmt.Sprintf("pow|%s|%d|%s|%s|%d", nonce, expires, ip, uaHash(ua), difficulty)
	sig = e.signChallenge(msg)
	return nonce, expires, sig
}

func (e *Engine) VerifyPoW(nonce string, expires int64, sig, solution, ip, ua string, difficulty int) bool {
	if nonce == "" || solution == "" || sig == "" {
		return false
	}
	if time.Now().Unix() > expires {
		return false
	}
	expected := e.signChallenge(fmt.Sprintf("pow|%s|%d|%s|%s|%d", nonce, expires, ip, uaHash(ua), difficulty))
	sigBytes, err1 := hex.DecodeString(sig)
	expBytes, err2 := hex.DecodeString(expected)
	if err1 != nil || err2 != nil || !hmac.Equal(sigBytes, expBytes) {
		return false
	}
	h := sha256.Sum256([]byte(nonce + ":" + solution))
	return hasLeadingZeroBits(h[:], difficulty)
}

func (e *Engine) IssueClearanceCookie(ip, ua string, secure bool) *http.Cookie {
	exp := time.Now().Add(DefaultClearanceTTL).Unix()
	mac := e.signChallenge(fmt.Sprintf("clr|%d|%s|%s", exp, ip, uaHash(ua)))
	return &http.Cookie{
		Name:     ClearanceCookieName,
		Value:    fmt.Sprintf("%d.%s", exp, mac),
		Path:     "/",
		MaxAge:   int(DefaultClearanceTTL.Seconds()),
		HttpOnly: true,
		Secure:   secure,
		SameSite: http.SameSiteLaxMode,
	}
}

func (e *Engine) HasValidClearance(r *http.Request, ip string) bool {
	c, err := r.Cookie(ClearanceCookieName)
	if err != nil || c == nil || c.Value == "" {
		return false
	}
	parts := strings.SplitN(c.Value, ".", 2)
	if len(parts) != 2 {
		return false
	}
	exp, err := strconv.ParseInt(parts[0], 10, 64)
	if err != nil || time.Now().Unix() > exp {
		return false
	}
	expected := e.signChallenge(fmt.Sprintf("clr|%d|%s|%s", exp, ip, uaHash(r.UserAgent())))
	gotBytes, err1 := hex.DecodeString(parts[1])
	expBytes, err2 := hex.DecodeString(expected)
	if err1 != nil || err2 != nil {
		return false
	}
	return hmac.Equal(gotBytes, expBytes)
}

func RenderChallengeHTML(host, nonce string, expires int64, sig string, difficulty int, redirectURI string) string {
	escHost := html.EscapeString(host)
	escNonce := html.EscapeString(nonce)
	escSig := html.EscapeString(sig)
	escRedir := html.EscapeString(redirectURI)
	return fmt.Sprintf(`<!DOCTYPE html>
<html lang="id" class="dark">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>Verifikasi Keamanan Browser — Athena Shield</title>
<style>
  body { margin:0; font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif; background:#09090b; color:#fafafa; min-height:100vh; display:flex; align-items:center; justify-content:center; padding:24px; }
  .card { max-width:420px; width:100%%; background:#111113; border:1px solid #27272a; border-radius:14px; padding:28px; box-shadow:0 20px 45px rgba(0,0,0,.55); text-align:center; }
  .badge { display:inline-block; font-size:11px; font-weight:600; color:#F5973E; background:#18181b; border:1px solid #27272a; padding:4px 10px; border-radius:999px; margin-bottom:14px; }
  h1 { font-size:17px; font-weight:600; margin:0 0 8px; letter-spacing:-0.01em; }
  p { font-size:13px; color:#a1a1aa; margin:0 0 20px; line-height:1.5; }
  .spinner { width:34px; height:34px; border:3px solid #27272a; border-top-color:#1D5CE0; border-radius:50%%; margin:0 auto 14px; animation:spin .8s linear infinite; }
  @keyframes spin { to { transform:rotate(360deg); } }
  .status { font-size:12px; color:#71717a; font-family:ui-monospace, SFMono-Regular, Menlo, monospace; }
</style>
</head>
<body>
  <div class="card">
    <div class="badge">Athena Shield Protection</div>
    <div class="spinner"></div>
    <h1>Memverifikasi browser Anda...</h1>
    <p>Sedang melakukan pemeriksaan keamanan otomatis sebelum mengakses <strong>%s</strong>. Proses ini hanya memerlukan beberapa detik.</p>
    <div id="st" class="status">Menyiapkan Proof-of-Work (%d-bit)...</div>
    <form id="cf" method="POST" action="%s">
      <input type="hidden" name="nonce" value="%s">
      <input type="hidden" name="expires" value="%d">
      <input type="hidden" name="sig" value="%s">
      <input type="hidden" name="solution" id="sol" value="">
      <input type="hidden" name="redirect" value="%s">
    </form>
  </div>
<script>
(function(){
  const nonce = %q;
  const diff = %d;
  const st = document.getElementById('st');
  function checkBits(bytes, bits){
    const fb = bits >> 3, rb = bits & 7;
    for(let i=0;i<fb;i++) if(bytes[i]!==0) return false;
    if(rb>0){ const m=(0xff<<(8-rb))&0xff; if((bytes[fb]&m)!==0) return false; }
    return true;
  }
  function sha256Fallback(str){
    function rr(n,x){return (x>>>n)|(x<<(32-n));}
    const K=[0x428a2f98,0x71374491,0xb5c0fbcf,0xe9b5dba5,0x3956c25b,0x59f111f1,0x923f82a4,0xab1c5ed5,0xd807aa98,0x12835b01,0x243185be,0x550c7dc3,0x72be5d74,0x80deb1fe,0x9bdc06a7,0xc19bf174,0xe49b69c1,0xefbe4786,0x0fc19dc6,0x240ca1cc,0x2de92c6f,0x4a7484aa,0x5cb0a9dc,0x76f988da,0x983e5152,0xa831c66d,0xb00327c8,0xbf597fc7,0xc6e00bf3,0xd5a79147,0x06ca6351,0x14292967,0x27b70a85,0x2e1b2138,0x4d2c6dfc,0x53380d13,0x650a7354,0x766a0abb,0x81c2c92e,0x92722c85,0xa2bfe8a1,0xa81a664b,0xc24b8b70,0xc76c51a3,0xd192e819,0xd6990624,0xf40e3585,0x106aa070,0x19a4c116,0x1e376c08,0x2748774c,0x34b0bcb5,0x391c0cb3,0x4ed8aa4a,0x5b9cca4f,0x682e6ff3,0x748f82ee,0x78a5636f,0x84c87814,0x8cc70208,0x90befffa,0xa4506ceb,0xbef9a3f7,0xc67178f2];
    const b=new TextEncoder().encode(str), l=b.length*8;
    const p=new Uint8Array(((b.length+9+63)>>6)<<6);
    p.set(b); p[b.length]=0x80;
    const dv=new DataView(p.buffer); dv.setUint32(p.length-4,l,false);
    let H=[0x6a09e667,0xbb67ae85,0x3c6ef372,0xa54ff53a,0x510e527f,0x9b05688c,0x1f83d9ab,0x5be0cd19];
    const w=new Uint32Array(64);
    for(let i=0;i<p.length;i+=64){
      for(let j=0;j<16;j++) w[j]=dv.getUint32(i+j*4,false);
      for(let j=16;j<64;j++){const s0=rr(7,w[j-15])^rr(18,w[j-15])^(w[j-15]>>>3);const s1=rr(17,w[j-2])^rr(19,w[j-2])^(w[j-2]>>>10);w[j]=(w[j-16]+s0+w[j-7]+s1)>>>0;}
      let [a,b0,c,d,e,f,g,h]=H;
      for(let j=0;j<64;j++){
        const S1=rr(6,e)^rr(11,e)^rr(25,e), ch=(e&f)^((~e)&g), t1=(h+S1+ch+K[j]+w[j])>>>0;
        const S0=rr(2,a)^rr(13,a)^rr(22,a), maj=(a&b0)^(a&c)^(b0&c), t2=(S0+maj)>>>0;
        h=g;g=f;f=e;e=(d+t1)>>>0;d=c;c=b0;b0=a;a=(t1+t2)>>>0;
      }
      H=[(H[0]+a)>>>0,(H[1]+b0)>>>0,(H[2]+c)>>>0,(H[3]+d)>>>0,(H[4]+e)>>>0,(H[5]+f)>>>0,(H[6]+g)>>>0,(H[7]+h)>>>0];
    }
    const out=new Uint8Array(32), odv=new DataView(out.buffer);
    for(let i=0;i<8;i++) odv.setUint32(i*4,H[i],false);
    return out;
  }
  async function digest(s){
    if(window.crypto && window.crypto.subtle){
      const buf=await window.crypto.subtle.digest('SHA-256', new TextEncoder().encode(s));
      return new Uint8Array(buf);
    }
    return sha256Fallback(s);
  }
  async function solve(){
    let i=0;
    while(true){
      const h = await digest(nonce+':'+i);
      if(checkBits(h, diff)){
        st.textContent='Verifikasi berhasil. Mengalihkan...';
        document.getElementById('sol').value=String(i);
        document.getElementById('cf').submit();
        return;
      }
      i++;
      if(i%%500===0) await new Promise(r=>setTimeout(r,0));
    }
  }
  solve();
})();
</script>
</body>
</html>`, escHost, difficulty, ChallengeVerifyPath, escNonce, expires, escSig, escRedir, nonce, difficulty)
}
