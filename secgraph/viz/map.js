"use strict";
// sec-graph interactive map (ADR-012). Self-contained: hand-rolled deterministic force layout +
// Canvas renderer + interactions, no libraries. Colour = security only; glow = unguarded only.
(function () {
const GRAPH = JSON.parse(document.getElementById("secgraph-graph").textContent);
const FIND  = JSON.parse(document.getElementById("secgraph-findings").textContent);

const LAYER_COLOR = {credentials:"#c98a1e", pii:"#8e7cc3", "untrusted-input":"#4c9dff",
                     "dangerous-sink":"#d1495b", auth:"#2a9d8f"};
const DATA_PRIORITY = ["credentials","pii","untrusted-input"];   // node fill picks the strongest
const SINK = "#d1495b";
const SEV_W = {critical:3.5, high:3, medium:2.25, low:1.5};

// ---- deterministic PRNG (mulberry32 seeded by FNV-1a of the id) --------------------
function fnv(s){let h=0x811c9dc5;for(let i=0;i<s.length;i++){h^=s.charCodeAt(i);h=Math.imul(h,0x01000193);}return h>>>0;}
function mulberry(a){return function(){a|=0;a=a+0x6D2B79F5|0;let t=Math.imul(a^a>>>15,1|a);t=t+Math.imul(t^t>>>7,61|t)^t;return((t^t>>>14)>>>0)/4294967296;};}

// ---- model -------------------------------------------------------------------------
const N = new Map();                       // id -> node
for (const n of GRAPH.nodes) {
  if (n.file_type === "rationale") continue;
  n.deg = 0;
  n.isFile = !String(n.label||"").endsWith(")");   // functions/methods end in "()"; files & classes don't
  n.layers = new Set(n.sec_layers || []);
  N.set(n.id, n);
}
const LINKS = [];
for (const e of GRAPH.links) {
  const a = N.get(e.source), b = N.get(e.target);
  if (!a || !b || a === b) continue;
  LINKS.push({a, b, rel: e.relation});
  a.deg++; b.deg++;
}
// findings -> routes; tag node security roles
const ROUTES = [];
for (const f of FIND) {
  const src = f.source_node && N.get(f.source_node);
  const sink = f.sink_node && N.get(f.sink_node);
  f._src = src || null; f._sink = sink || null;
  const dataLayer = DATA_PRIORITY.find(l => (f.layers||[]).includes(l)) || "untrusted-input";
  f._color = LAYER_COLOR[dataLayer] || "#4c9dff";
  if (src) { src.isSource = true; src.dataColor = strongest(src.dataColor, dataLayer); markGuard(src, f); }
  if (sink) { sink.isSink = true; markGuard(sink, f); }
  if (src && sink) ROUTES.push(f);
}
function strongest(cur, layer){ if (!cur) return layer;
  return DATA_PRIORITY.indexOf(layer) < DATA_PRIORITY.indexOf(cur) ? layer : cur; }
// guard_status "unknown" (an ingested finding we could not analyze) claims NEITHER verdict:
// no red glow AND no green ring -- ADR-010's asymmetry without a false glow. Missing guard_status
// (the built-in engine, which always analyzes) is treated as analyzed.
function markGuard(node, f){ if (f.guard_status==="unknown") return; if (f.unguarded) node.unguarded = true; else node.guarded = true; }

// security neighborhood = finding endpoints + their files + 1-hop call neighbors
const CORE = new Set();
for (const f of FIND){ if (f._src) CORE.add(f._src); if (f._sink) CORE.add(f._sink); }
const NEIGH = new Set(CORE);
for (const {a,b,rel} of LINKS){
  if (rel === "contains" && (CORE.has(b))) NEIGH.add(a);              // the file
  if (rel === "calls" && (CORE.has(a) || CORE.has(b))) { NEIGH.add(a); NEIGH.add(b); }
}

// ---- deterministic seed positions (phyllotaxis per community) ----------------------
const comm = new Map();
[...N.values()].sort((x,y)=>(x.community-y.community)||(x.id<y.id?-1:1)).forEach(n=>{
  const c = n.community||0; if(!comm.has(c)) comm.set(c,{n:0});
  const g = comm.get(c); const k = g.n++;
  const rnd = mulberry(0x5EC6A9 ^ fnv(n.id));
  const R = 30*Math.sqrt(k+1), ang = (k+1)*2.399963;
  n.x = Math.cos(ang)*R + (rnd()-0.5)*4; n.y = Math.sin(ang)*R + (rnd()-0.5)*4;
});
// spread communities on a ring so clusters become separated "continents"
const clist=[...comm.keys()].sort((a,b)=>a-b);
clist.forEach((c,i)=>{const a=i/clist.length*6.28318, R=260*Math.sqrt(clist.length);
  const cx=Math.cos(a)*R, cy=Math.sin(a)*R; comm.get(c).cx=cx; comm.get(c).cy=cy;});
for(const n of N.values()){const g=comm.get(n.community||0); n.x+=g.cx; n.y+=g.cy; n.vx=0; n.vy=0;
  n.r = n.isFile ? 8 : Math.max(4, Math.min(10, 4*(1+0.16*Math.sqrt(n.deg))));}

// ---- Barnes-Hut quadtree (repulsion + hit-testing) ---------------------------------
function buildQT(nodes){
  let minx=1e9,miny=1e9,maxx=-1e9,maxy=-1e9;
  for(const n of nodes){minx=Math.min(minx,n.x);miny=Math.min(miny,n.y);maxx=Math.max(maxx,n.x);maxy=Math.max(maxy,n.y);}
  const size=Math.max(maxx-minx,maxy-miny,1)+1;
  const root={x:minx,y:miny,s:size,m:0,cx:0,cy:0,node:null,kids:null};
  function insert(q,n,depth){
    if(q.node===null&&q.kids===null){q.node=n;q.m=1;q.cx=n.x;q.cy=n.y;return;}
    if(depth>48){q.m++;q.cx+=(n.x-q.cx)/q.m;q.cy+=(n.y-q.cy)/q.m;return;}   // coincident-point guard
    if(q.kids===null){const old=q.node;q.node=null;q.kids=[null,null,null,null];place(q,old,depth);}
    q.m++;q.cx+=(n.x-q.cx)/q.m;q.cy+=(n.y-q.cy)/q.m;place(q,n,depth);
  }
  function place(q,n,depth){const half=q.s/2;const i=(n.x>=q.x+half?1:0)+(n.y>=q.y+half?2:0);
    let k=q.kids[i]; if(!k){k=q.kids[i]={x:q.x+(i&1?half:0),y:q.y+(i&2?half:0),s:half,m:0,cx:0,cy:0,node:null,kids:null};}
    insert(k,n,depth+1);}
  for(const n of nodes) insert(root,n,0);
  return root;
}
function repulse(q,n,theta,k){
  if(q.m===0||(q.node===n&&q.kids===null))return;
  let dx=q.cx-n.x, dy=q.cy-n.y, d2=dx*dx+dy*dy; if(d2<1)d2=1;
  if(q.kids===null || (q.s*q.s)/d2 < theta*theta){
    const d=Math.sqrt(d2); const f=-k*q.m/d2; n.vx+=f*dx/d; n.vy+=f*dy/d; return;
  }
  for(const c of q.kids) if(c) repulse(c,n,theta,k);
}

// ---- force simulation --------------------------------------------------------------
let alpha=1;
function tick(nodes, links){
  const qt=buildQT(nodes);
  for(const n of nodes){ if(n===drag) continue;
    repulse(qt,n,0.85,(n.isFile?3000:1300)*alpha);
    const g=comm.get(n.community||0);                     // community anchor (weak: position, not collapse)
    n.vx += (g.cx-n.x)*0.026*alpha; n.vy += (g.cy-n.y)*0.026*alpha;
    n.vx += (-n.x)*0.006*alpha; n.vy += (-n.y)*0.006*alpha;   // gentle global centering
  }
  for(const L of links){                                  // springs
    const rest = L.rel==="contains"?95:L.rel==="calls"?150:210;
    const kk = (L.rel==="contains"?0.7:L.rel==="calls"?0.22:0.08)/Math.min(L.a.deg,L.b.deg,8)*alpha;
    let dx=L.b.x-L.a.x, dy=L.b.y-L.a.y, d=Math.hypot(dx,dy)||1; const f=(d-rest)*kk;
    dx/=d; dy/=d; if(L.a!==drag){L.a.vx+=f*dx;L.a.vy+=f*dy;} if(L.b!==drag){L.b.vx-=f*dx;L.b.vy-=f*dy;}
  }
  for(const n of nodes){ if(n===drag){continue;} n.vx*=0.62; n.vy*=0.62;
    n.x+=Math.max(-30,Math.min(30,n.vx)); n.y+=Math.max(-30,Math.min(30,n.vy)); }
  if(nodes.length<=700){                                  // pairwise collision -> readable, no overlap
    for(let i=0;i<nodes.length;i++)for(let j=i+1;j<nodes.length;j++){
      const a=nodes[i],b=nodes[j];let dx=b.x-a.x,dy=b.y-a.y,d=Math.hypot(dx,dy)||1;
      const min=a.r+b.r+48; if(d<min){const p=(min-d)/d*0.5*dx,q=(min-d)/d*0.5*dy;
        if(a!==drag){a.x-=p;a.y-=q;} if(b!==drag){b.x+=p;b.y+=q;}}
    }
  }
  alpha*=0.985; if(alpha<0.02)alpha=0.02;
}
function settle(nodes,links,n){const a=alpha;alpha=1;for(let i=0;i<n;i++)tick(nodes,links);alpha=Math.min(a,0.05);}

// ---- state / filters ---------------------------------------------------------------
const DATA_LAYERS = new Set(DATA_PRIORITY);   // dangerous-sink is universal
const activeLayers = new Set(DATA_LAYERS);
let onlyUnguarded=false, fullGraph=false, criticalOnly=false, focusF=null, hoverN=null, selN=null;
function isCritical(f){return f.unguarded && ((f.layers||[]).includes("credentials")||(f.layers||[]).includes("pii"));}
function findingVisible(f){
  if(criticalOnly) return isCritical(f);
  if(onlyUnguarded && !f.unguarded) return false;
  // toggle on the DATA layer only (every finding also carries dangerous-sink, so OR-ing it would
  // make the toggles inert); a finding shows if any of its data layers is active
  return (f.layers||[]).some(l=>DATA_LAYERS.has(l) && activeLayers.has(l));
}
function visibleNodes(){
  if(fullGraph || FIND.length===0 || NEIGH.size===0) return [...N.values()];   // no bind -> full graph, never blank
  return [...N.values()].filter(n=>NEIGH.has(n));
}
function nodeShown(n){ return fullGraph || FIND.length===0 || NEIGH.size===0 || NEIGH.has(n); }
function secNodesOf(){ const s=new Set();
  for(const f of FIND){ if(!findingVisible(f))continue; if(f._src)s.add(f._src); if(f._sink)s.add(f._sink); } return s; }

// ---- camera ------------------------------------------------------------------------
let scale=1, tx=0, ty=0;
const cv=document.getElementById("map"), ctx=cv.getContext("2d");
let W=0,H=0,DPR=1;
function resize(){DPR=Math.min(2,window.devicePixelRatio||1);W=cv.clientWidth;H=cv.clientHeight;
  cv.width=W*DPR;cv.height=H*DPR;}
function fit(nodes){ nodes=(nodes||visibleNodes()).filter(n=>n); if(!nodes.length)return;
  let a=1e9,b=1e9,c=-1e9,d=-1e9;
  for(const n of nodes){a=Math.min(a,n.x);b=Math.min(b,n.y);c=Math.max(c,n.x);d=Math.max(d,n.y);}
  const pad=70, sw=W-2*pad, sh=H-2*pad;
  scale=Math.max(0.06,Math.min(2.4,Math.min(sw/Math.max(c-a,1),sh/Math.max(d-b,1))));
  tx=W/2-((a+c)/2)*scale; ty=H/2-((b+d)/2)*scale;
}
function SX(n){return n.x*scale+tx;} function SY(n){return n.y*scale+ty;}

// ---- palette (from CSS vars, theme-aware) ------------------------------------------
let PAL={};
function palette(){const cs=getComputedStyle(document.documentElement);
  PAL={edge:cs.getPropertyValue("--edge").trim(),node:cs.getPropertyValue("--node").trim(),
       line:cs.getPropertyValue("--line").trim(),muted:cs.getPropertyValue("--muted").trim(),
       fg:cs.getPropertyValue("--fg").trim(),canvas:cs.getPropertyValue("--canvas").trim()};}

// ---- render ------------------------------------------------------------------------
let pulse=0;
function draw(){
  pulse=(pulse+0.03)%(Math.PI*2);
  ctx.setTransform(DPR,0,0,DPR,0,0); ctx.clearRect(0,0,W,H);
  const focusSet=(focusF&&focusF._src&&focusF._sink)?new Set([focusF._src,focusF._sink]):null;
  const dim=n=> focusSet ? (focusSet.has(n)?1:0.09) : (selN? (n===selN||neighborOf(n,selN)?1:0.16):1);
  const sec=secNodesOf();   // nodes on a currently-visible finding -> only these carry security decoration

  // structural edges
  ctx.lineWidth=1;
  for(const L of LINKS){ if(!nodeShown(L.a)||!nodeShown(L.b))continue; if(L.rel==="rationale_for")continue;
    const o=(focusF?0.05:(L.rel==="contains"?0.11:0.3))*Math.min(dim(L.a),dim(L.b));
    ctx.globalAlpha=o; ctx.strokeStyle=L.rel==="calls"?PAL.muted:PAL.edge;
    ctx.beginPath();ctx.moveTo(SX(L.a),SY(L.a));ctx.lineTo(SX(L.b),SY(L.b));ctx.stroke();
  }
  ctx.globalAlpha=1;
  // taint routes
  for(const f of ROUTES){ if(!findingVisible(f))continue; if(focusF&&f!==focusF)continue;
    const s=f._src,t=f._sink; if(!nodeShown(s)||!nodeShown(t))continue;
    if(s===t) continue;   // source & sink fall on the SAME graph node -- an intra-function flow (source
    drawRoute(s,t,f,focusF?1:dim(s));   // and sink inside one def) or a located point. There is no
  }                       // inter-node structure to draw: the node's own mark + unguarded glow carries
                          // it, and the full statement-level trace lives in the detail card / sidebar.
  // nodes
  for(const n of N.values()){ if(!nodeShown(n))continue;
    const a=dim(n); if(a<=0.02)continue;
    const on=sec.has(n);   // participates in a currently-visible finding
    const x=SX(n),y=SY(n),r=Math.max(2.2,n.r*Math.min(1.4,Math.max(0.6,scale)));
    if(on&&n.unguarded){ const pr=r*2.4*(1+0.12*Math.sin(pulse));
      const g=ctx.createRadialGradient(x,y,r*0.6,x,y,pr);
      g.addColorStop(0,"rgba(229,72,77,"+(0.42*a)+")");g.addColorStop(1,"rgba(229,72,77,0)");
      ctx.fillStyle=g;ctx.beginPath();ctx.arc(x,y,pr,0,6.2832);ctx.fill();}
    ctx.globalAlpha=a;
    let fill=PAL.node, rr=r;
    if(on){ if(n.isSink){fill=SINK;rr=r*1.5;} if(n.isSource){fill=LAYER_COLOR[n.dataColor]||fill;rr=r*1.5;} }
    ctx.fillStyle=fill;
    if(n.isFile){ctx.beginPath();rrect(x-rr,y-rr,rr*2,rr*2,3);ctx.fill();
      ctx.lineWidth=1;ctx.strokeStyle=PAL.line;ctx.stroke();}
    else{ctx.beginPath();ctx.arc(x,y,rr,0,6.2832);ctx.fill();}
    if(on&&n.guarded&&!n.unguarded){ctx.lineWidth=2;ctx.strokeStyle="#2a9d8f";     // guarded: green ring only
      ctx.beginPath();ctx.arc(x,y,rr+2.5,0,6.2832);ctx.stroke();}
    ctx.globalAlpha=1;
  }
  // labels (LOD: hero/hover/selected always; others when zoomed in)
  ctx.textAlign="center";ctx.textBaseline="top";
  for(const n of N.values()){ if(!nodeShown(n))continue; const a=dim(n); if(a<0.5)continue;
    const hero=n.isSource||n.isSink; const show= n===hoverN||n===selN||(focusF&&focusSet.has(n))||(hero&&scale>0.35)||scale>0.9;
    if(!show)continue;
    ctx.globalAlpha=Math.min(1,a);ctx.fillStyle= hero?PAL.fg:PAL.muted;
    ctx.font=(hero?"600 ":"")+"11px -apple-system,Menlo,monospace";
    const lbl=String(n.label||"").replace(/\(\)$/,"");
    ctx.fillText(lbl.length>26?lbl.slice(0,25)+"…":lbl, SX(n), SY(n)+n.r*1.4+3);
  }
  ctx.globalAlpha=1;
  requestAnimationFrame(draw);
}
function rrect(x,y,w,h,r){ctx.moveTo(x+r,y);ctx.arcTo(x+w,y,x+w,y+h,r);ctx.arcTo(x+w,y+h,x,y+h,r);
  ctx.arcTo(x,y+h,x,y,r);ctx.arcTo(x,y,x+w,y,r);ctx.closePath();}
function drawRoute(s,t,f,a){                                   // only ever called for s!==t (inter-node)
  const x1=SX(s),y1=SY(s),x2=SX(t),y2=SY(t);
  const mx=(x1+x2)/2,my=(y1+y2)/2, nx=-(y2-y1),ny=(x2-x1),nl=Math.hypot(nx,ny)||1;
  const off=Math.min(60,Math.hypot(x2-x1,y2-y1)*0.18)+ (f._idx||0)*7;
  const cx=mx+nx/nl*off, cy=my+ny/nl*off;
  if(f.unguarded){ctx.save();ctx.shadowColor="rgba(229,72,77,0.7)";ctx.shadowBlur=12+4*Math.sin(pulse);}
  const grad=ctx.createLinearGradient(x1,y1,x2,y2);
  grad.addColorStop(0,f._color);grad.addColorStop(1,SINK);
  ctx.globalAlpha=Math.max(0.5,a);ctx.strokeStyle=grad;ctx.lineWidth=(SEV_W[f.severity]||2)+(f===focusF?1.5:0);
  ctx.beginPath();ctx.moveTo(x1,y1);ctx.quadraticCurveTo(cx,cy,x2,y2);ctx.stroke();
  if(f.unguarded)ctx.restore();
  // arrowhead at sink
  const ang=Math.atan2(y2-cy,x2-cx);ctx.fillStyle=SINK;ctx.globalAlpha=Math.max(0.5,a);
  ctx.beginPath();ctx.moveTo(x2,y2);ctx.lineTo(x2-9*Math.cos(ang-0.4),y2-9*Math.sin(ang-0.4));
  ctx.lineTo(x2-9*Math.cos(ang+0.4),y2-9*Math.sin(ang+0.4));ctx.closePath();ctx.fill();
  ctx.globalAlpha=1;
}
const NEIGHBORS=new Map();
for(const L of LINKS){(NEIGHBORS.get(L.a)||NEIGHBORS.set(L.a,new Set()).get(L.a)).add(L.b);
  (NEIGHBORS.get(L.b)||NEIGHBORS.set(L.b,new Set()).get(L.b)).add(L.a);}
function neighborOf(n,c){const s=NEIGHBORS.get(c);return s&&s.has(n);}
ROUTES.forEach((f,i)=>{f._idx=i;});

// ---- hit testing -------------------------------------------------------------------
function pick(mx,my){ let best=null,bd=1e9;
  for(const n of N.values()){ if(!nodeShown(n))continue;
    const dx=SX(n)-mx,dy=SY(n)-my,d=dx*dx+dy*dy; const rad=Math.max(n.r*scale+5,11);
    if(d<rad*rad&&d<bd){bd=d;best=n;} }
  return best;
}

// ---- interactions ------------------------------------------------------------------
let drag=null,panning=false,px=0,py=0,moved=false;
cv.addEventListener("mousedown",e=>{const n=pick(e.offsetX,e.offsetY);moved=false;px=e.offsetX;py=e.offsetY;
  if(n){drag=n;}else{panning=true;}});
window.addEventListener("mousemove",e=>{
  const r=cv.getBoundingClientRect(),mx=e.clientX-r.left,my=e.clientY-r.top;
  if(drag){drag.x=(mx-tx)/scale;drag.y=(my-ty)/scale;alpha=Math.max(alpha,0.25);moved=true;return;}
  if(panning){tx+=e.clientX-r.left-px;ty+=e.clientY-r.top-py;px=mx;py=my;moved=true;return;}
  const n=pick(mx,my); if(n!==hoverN){hoverN=n;tooltip(n,e.clientX,e.clientY);}
  cv.style.cursor=n?"pointer":(panning?"grabbing":"grab");
});
window.addEventListener("mouseup",()=>{ if(drag){drag=null;} if(panning)panning=false;});
cv.addEventListener("click",e=>{ if(moved)return; const n=pick(e.offsetX,e.offsetY);
  if(n){selN=(selN===n?null:n);focusF=null;renderPanel();syncRows();}else{selN=null;focusF=null;renderPanel();syncRows();}});
cv.addEventListener("wheel",e=>{e.preventDefault();const r=cv.getBoundingClientRect();
  const mx=e.clientX-r.left,my=e.clientY-r.top,f=Math.pow(1.0015,-e.deltaY);
  const ns=Math.max(0.05,Math.min(8,scale*f));const k=ns/scale;
  tx=mx-(mx-tx)*k;ty=my-(my-ty)*k;scale=ns;},{passive:false});
cv.addEventListener("dblclick",e=>{const f=Math.pow(1.3,1);const r=cv.getBoundingClientRect();
  const mx=e.clientX-r.left,my=e.clientY-r.top;tx=mx-(mx-tx)*f;ty=my-(my-ty)*f;scale*=f;});

function tooltip(n,cx,cy){const el=document.getElementById("tip");
  if(!n){el.hidden=true;return;}
  el.hidden=false;el.style.left=(cx+14)+"px";el.style.top=(cy+14)+"px";
  const cnt=FIND.filter(f=>f._src===n||f._sink===n).length;
  el.textContent="";const t=document.createElement("div");t.className="t";
  t.textContent=String(n.label||n.id);const m=document.createElement("div");m.className="m";
  m.textContent=(n.source_file||"")+" "+(n.source_location||"")+(cnt?"  ·  "+cnt+" path"+(cnt>1?"s":""):"")
    +([...n.layers].length?"  ·  "+[...n.layers].join(", "):"");
  el.append(t,m);}

// ---- layer rail / presets ----------------------------------------------------------
function buildRail(){
  const box=document.getElementById("layers"); box.textContent="";
  const present=[...new Set(FIND.flatMap(f=>f.layers||[]))].filter(l=>DATA_LAYERS.has(l)).sort();
  for(const L of present){
    const row=document.createElement("label");row.className="layer";
    const cb=document.createElement("input");cb.type="checkbox";cb.checked=activeLayers.has(L);
    cb.onchange=()=>{cb.checked?activeLayers.add(L):activeLayers.delete(L);criticalOnly=false;preset.classList.remove("on");refit();};
    const dot=document.createElement("span");dot.className="dot";dot.style.background=LAYER_COLOR[L]||"#888";
    const t=document.createElement("span");t.textContent=L;
    const ct=document.createElement("span");ct.className="ct";ct.textContent=FIND.filter(f=>(f.layers||[]).includes(L)).length;
    row.append(cb,dot,t,ct);box.append(row);
  }
  const leg=document.getElementById("legend");
  [["#c98a1e","credentials source"],["#8e7cc3","PII source"],["#d1495b","dangerous sink"],
   ["#2a9d8f","guarded (auth)"],["#e5484d","UNGUARDED (glow)"]].forEach(([c,l])=>{
    const r=document.createElement("div");r.className="row";const m=document.createElement("span");
    m.className="mk";m.style.background=c;const s=document.createElement("span");s.textContent=l;r.append(m,s);leg.append(r);});
}
const preset=document.getElementById("preset-critical");
preset.onclick=()=>{criticalOnly=!criticalOnly;preset.classList.toggle("on",criticalOnly);
  if(criticalOnly){onlyUnguarded=false;document.getElementById("only-unguarded").checked=false;}
  refit();};
document.getElementById("only-unguarded").onchange=e=>{onlyUnguarded=e.target.checked;criticalOnly=false;preset.classList.remove("on");refit();};
document.getElementById("full-graph").onchange=e=>{fullGraph=e.target.checked;refit();};
document.getElementById("fit").onclick=()=>fit();
function refit(){ const vis=ROUTES.filter(findingVisible); focusF=null; selN=null;
  const nodes=vis.length?[...new Set(vis.flatMap(f=>[f._src,f._sink]))]:visibleNodes();
  fit(nodes); renderList(); }

// ---- findings sidebar + detail panel ----------------------------------------------
function renderList(){
  const p=document.getElementById("panel");p.textContent="";
  const head=document.createElement("div");head.className="sidehead";
  const shown=FIND.filter(findingVisible);
  head.textContent=shown.length+" of "+FIND.length+" path"+(FIND.length===1?"":"s");
  p.append(head);
  if(!shown.length){const e=document.createElement("div");e.className="empty";e.textContent="No paths match the filters.";p.append(e);return;}
  const order={critical:0,high:1,medium:2,low:3};
  shown.sort((a,b)=>(a.unguarded?0:1)-(b.unguarded?0:1)||(order[a.severity]||9)-(order[b.severity]||9)||a.id.localeCompare(b.id));
  for(const f of shown){
    const row=document.createElement("div");row.className="frow";row.dataset.id=f.id;
    const sev=document.createElement("span");sev.className="sev";sev.style.background=sevColor(f.severity);
    const ff=document.createElement("div");ff.className="ff";
    const fl=document.createElement("div");fl.className="fl";fl.textContent=f.source_id+" → "+f.sink_id;
    const fm=document.createElement("div");fm.className="fm";fm.textContent=(f.cwe?f.cwe+" · ":"")+(f.trace&&f.trace.length?f.trace.join(" → "):f.function);
    ff.append(fl,fm);
    row.append(sev,ff);
    const un=f.guard_status==="unknown";
    const badge=document.createElement("span");badge.className="badge "+(un?"unk":f.unguarded?"ung":"grd");
    badge.textContent=un?"guards ?":f.unguarded?"UNGUARDED":"guarded";row.append(badge);
    row.onclick=()=>focusFinding(f);
    p.append(row);
  }
  syncRows();
}
function focusFinding(f){ focusF=f; selN=null;
  if(f._src&&f._sink){fit([f._src,f._sink]); if(scale>2.2)scale=2.2;} renderPanel(); syncRows();
}
function syncRows(){document.querySelectorAll(".frow").forEach(r=>r.classList.toggle("sel",focusF&&r.dataset.id===focusF.id));}
function renderPanel(){
  if(!focusF && !selN){ renderList(); return; }
  const p=document.getElementById("panel");p.textContent="";
  const head=document.createElement("div");head.className="sidehead";
  const back=document.createElement("button");back.className="back";back.textContent="‹ all paths";
  back.onclick=()=>{focusF=null;selN=null;renderList();};head.append(back);p.append(head);
  if(selN&&!focusF){ // node view
    const list=FIND.filter(f=>f._src===selN||f._sink===selN);
    const t=document.createElement("div");t.className="card";
    const h=document.createElement("div");h.style.fontWeight="600";h.style.marginBottom="6px";
    h.textContent=String(selN.label||selN.id);t.append(h);
    const m=document.createElement("div");m.style.color="var(--muted)";m.style.fontSize="12px";
    m.textContent=(selN.source_file||"")+" "+(selN.source_location||"")+" · "+list.length+" path"+(list.length===1?"":"s");t.append(m);p.append(t);
    list.forEach(f=>p.append(finRow(f)));return;
  }
  p.append(card(focusF));
}
function finRow(f){const row=document.createElement("div");row.className="frow";
  const sev=document.createElement("span");sev.className="sev";sev.style.background=sevColor(f.severity);
  const ff=document.createElement("div");ff.className="ff";const fl=document.createElement("div");fl.className="fl";
  fl.textContent=f.source_id+" → "+f.sink_id;ff.append(fl);row.append(sev,ff);
  const un=f.guard_status==="unknown";
  const b=document.createElement("span");b.className="badge "+(un?"unk":f.unguarded?"ung":"grd");b.textContent=un?"guards ?":f.unguarded?"UNGUARDED":"guarded";
  row.append(b);row.onclick=()=>focusFinding(f);return row;}
function card(f){
  const c=document.createElement("div");c.className="card";
  const top=document.createElement("div");top.className="top";
  const sp=document.createElement("span");sp.className="sevpill "+f.severity;sp.textContent=f.severity;
  const cwe=document.createElement("span");cwe.className="cwe";cwe.textContent=(f.cwe||"")+" "+f.source_id+" → "+f.sink_id;
  top.append(sp,cwe);
  if(f.unguarded){const u=document.createElement("span");u.className="sevpill critical";u.textContent="UNGUARDED";top.append(u);}
  c.append(top);
  for(const [role,file,line] of [["source",f.source_file,f.source_line],["sink",f.sink_file||f.source_file,f.sink_line]]){
    const r=document.createElement("div");r.className="route";
    const nd=document.createElement("div");nd.className="rail-node";
    const ro=document.createElement("div");ro.className="role";ro.textContent=role;
    const lo=document.createElement("div");lo.className="loc";lo.textContent=file+":"+line;nd.append(ro,lo);r.append(nd);c.append(r);
  }
  if(f.trace&&f.trace.length){const tr=document.createElement("div");tr.className="trace";tr.textContent="trace: "+f.trace.join(" → ");c.append(tr);}
  for(const s of [f.source_slice,f.sink_slice]) if(s){const pre=document.createElement("pre");pre.textContent=s;c.append(pre);}
  const chips=document.createElement("div");chips.className="chips";
  for(const L of (f.layers||[])){const ch=document.createElement("span");ch.className="chip";ch.textContent=L;chips.append(ch);}
  if(f.guards&&f.guards.length){const g=document.createElement("span");g.className="chip grd";g.textContent="guarded by: "+f.guards.join(", ");chips.append(g);}
  c.append(chips);
  const conf=document.createElement("div");conf.style.color="var(--muted)";conf.style.fontSize="12px";conf.textContent="confidence: "+f.confidence;c.append(conf);
  const btn=document.createElement("button");btn.className="mcp";btn.textContent="Copy MCP command";
  btn.onclick=()=>{const cmd='get_path_slice("'+f.id+'")';
    (navigator.clipboard?navigator.clipboard.writeText(cmd):Promise.reject()).then(()=>flash(btn,"Copied ✓")).catch(()=>{
      const ta=document.createElement("textarea");ta.value=cmd;document.body.append(ta);ta.select();
      try{document.execCommand("copy");flash(btn,"Copied ✓");}catch(e){}ta.remove();});};
  c.append(btn);return c;
}
function flash(b,t){const o=b.textContent;b.textContent=t;setTimeout(()=>b.textContent=o,1200);}
function sevColor(s){return{critical:"#c1121f",high:"#d1495b",medium:"#c98a1e",low:"#5a7d9a"}[s]||"#888";}

// ---- search / keyboard / theme -----------------------------------------------------
document.getElementById("search").addEventListener("input",e=>{
  const q=e.target.value.trim().toLowerCase(); selN=null; focusF=null;
  if(!q){renderList();return;}
  const hit=[...N.values()].find(n=>nodeShown(n)&&(String(n.label||"").toLowerCase().includes(q)||String(n.source_file||"").toLowerCase().includes(q)));
  if(hit){selN=hit;fit([hit].concat([...(NEIGHBORS.get(hit)||[])]));if(scale>2)scale=2;renderPanel();syncRows();}
});
window.addEventListener("keydown",e=>{ if(e.target.tagName==="INPUT")return;
  if(e.key==="/"){e.preventDefault();document.getElementById("search").focus();}
  else if(e.key==="f"||e.key==="F")fit();
  else if(e.key==="Escape"){focusF=null;selN=null;renderList();}
  else if(e.key==="u"||e.key==="U"){const c=document.getElementById("only-unguarded");c.checked=!c.checked;c.onchange({target:c});}
  else if(e.key==="g"||e.key==="G"){const c=document.getElementById("full-graph");c.checked=!c.checked;c.onchange({target:c});}
});
document.getElementById("theme").onclick=()=>{const r=document.documentElement,cur=r.getAttribute("data-theme");
  const next=cur==="dark"?"light":cur==="light"?"dark":(matchMedia("(prefers-color-scheme: dark)").matches?"light":"dark");
  r.setAttribute("data-theme",next);palette();};

// ---- boot --------------------------------------------------------------------------
resize();palette();buildRail();
const nodes=[...N.values()], links=LINKS.filter(L=>L.rel!=="rationale_for");
settle(nodes,links, nodes.length>800?80:300);   // fewer settle ticks on a large repo (boot latency)
window.addEventListener("resize",()=>{resize();});
setInterval(()=>{ if(alpha>0.021) tick(nodes,links); },16);   // gentle live relax + drag
refit();
if(location.hash==="#critical") preset.click();               // deep-link to the Critical view
requestAnimationFrame(draw);
})();
