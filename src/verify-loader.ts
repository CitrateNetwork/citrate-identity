/**
 * CitrateLoader — the Citrate triangle mark that breaks into a spinning liquid ring
 * and reassembles (the "federated learning" brand animation). Dependency-free vanilla
 * port of `citrate-landing/src/components/loader/CitrateLoader.tsx` for the raw-HTML
 * `/verify` page (no React/build step). Emits the SVG markup + a `<script>` body that
 * exposes `window.startCitrateLoader(svgEl)` (returns a stop() fn).
 *
 * The mark is nine facets (`.pc`); each frame morphs every facet between its home slot
 * in the triangle and an evenly-spaced slot on a continuously spinning ring, peeling
 * out top-first clockwise (center facet last) and rebuilding in reverse.
 */

const PATHS: string[] = [
  'M40.05,65c2.21-.14,4.02-.63,5.3-1.1-1.94-2.21-3.88-4.41-5.82-6.62l-4.27,7.4c1.23.24,2.87.43,4.79.31Z',
  'M41.7,73.61c4.34-.04,7.98-.72,10.68-1.44-2.03-2.28-4.06-4.56-6.1-6.84-1.4.54-3.41,1.14-5.88,1.35-2.41.2-4.45-.04-5.9-.32l-3.47,6.01c2.71.66,6.35,1.28,10.68,1.24Z',
  'M53.37,74.02c-2.94.76-6.87,1.48-11.53,1.53-4.65.05-8.58-.59-11.53-1.28-.86,1.5-1.73,2.99-2.59,4.49-1.03,1.78.26,4.01,2.32,4.01h30.93c-2.53-2.92-5.06-5.83-7.59-8.75Z',
  'M62.58,47.91c.69-.85,1.4-1.69,2.13-2.51,1.49-1.69,3.08-3.3,4.81-4.74.92-.76,1.98-1.39,3.04-1.95.16-.08.32-.16.48-.25l-8.79-15.22c-1.03-1.78-3.6-1.78-4.63,0l-8.62,14.93c3.86,3.25,7.72,6.49,11.57,9.74Z',
  'M75.24,58.35c.44-.33.9-.66,1.37-.96,1.4-.89,2.8-1.77,4.27-2.56.5-.27,1.01-.53,1.52-.78l-8-13.85c-.86.42-1.69.9-2.48,1.43-.94.63-1.78,1.4-2.6,2.17-1.62,1.53-3.09,3.2-4.51,4.91-.17.2-.33.41-.5.61,3.64,3.01,7.29,6.02,10.93,9.03Z',
  'M79.77,57.69c-1.14.7-2.12,1.42-2.94,2.1,6.07,5.26,12.14,10.51,18.21,15.77l-11.43-19.8c-1.14.46-2.45,1.09-3.84,1.93Z',
  'M75.19,61.37s-.01.01-.02.01c-2.22,1.74-3.69,3.28-4.22,3.82-1.88,1.93-2.99,3.07-4.71,4.26-2.4,1.66-4.66,2.49-6.6,3.21-1.3.48-2.41.82-3.23,1.04,2.62,3.04,5.25,6.07,7.87,9.11h29.33c1.77,0,2.96-1.64,2.61-3.23-7.01-6.07-14.02-12.15-21.03-18.22Z',
  'M55.03,71.84c.12-.03.3-.07.51-.12,1.32-.33,3.76-.93,5.99-1.92,2.95-1.31,5-3.05,5.84-3.82,1.21-1.1,1.45-1.58,3.58-3.65,1.16-1.12,2.15-2,2.82-2.59-3.57-2.95-7.14-5.89-10.71-8.84-2.36,2.93-4.65,5.92-7.3,8.61-2.08,2.1-4.39,3.99-7.03,5.26l6.29,7.07Z',
  'M47.12,63.06c3.38-1.53,6.18-4.17,8.64-6.92,1.95-2.18,3.73-4.49,5.56-6.76-3.81-3.2-7.61-6.4-11.42-9.6l-9.21,15.96c2.14,2.44,4.29,4.88,6.43,7.32Z',
];

/** The loader SVG markup (assembled triangle; the script animates the `.pc` facets). */
export function citrateLoaderSvg(id: string): string {
  const paths = PATHS.map((d) => `<path class="pc" d="${d}"></path>`).join('');
  return `<svg id="${id}" class="citrate-loader" role="img" aria-label="Verifying" viewBox="11.63 2.14 100 100"><g>${paths}</g></svg>`;
}

/** Vanilla-JS animation engine, injected once into the page's <script>. */
export const CITRATE_LOADER_SCRIPT = `
window.startCitrateLoader = function(svg){
  var speed=2.1, cycle=11000, turns=1, hold=0.008, ramp=0.09, ringRadius=52, arcSweep=26, thickness=18;
  if (window.matchMedia && window.matchMedia('(prefers-reduced-motion: reduce)').matches) return function(){};
  var N=160, Cx=61.63, Cy=52.14, raf=0, arcKey='', arc=[], pieces=[], arcSign=0;
  function signedArea(pts){ var s=0; for(var i=0;i<pts.length;i++){ var a=pts[i], b=pts[(i+1)%pts.length]; s+=a.x*b.y-b.x*a.y; } return s/2; }
  function resample(pts,n){ var seg=[], total=0, i, j; for(i=0;i<pts.length;i++){ var a=pts[i], b=pts[(i+1)%pts.length]; var d=Math.hypot(b.x-a.x,b.y-a.y); seg.push(d); total+=d; } var out=[], step=total/n; i=0; var acc=0; for(j=0;j<n;j++){ var dist=j*step; while(i<seg.length-1 && acc+seg[i]<dist){ acc+=seg[i]; i++; } var aa=pts[i], bb=pts[(i+1)%pts.length]; var f=seg[i]?(dist-acc)/seg[i]:0; out.push({x:aa.x+(bb.x-aa.x)*f,y:aa.y+(bb.y-aa.y)*f}); } return out; }
  function buildArc(R,sweepDeg,tMax,n){ var sweep=sweepDeg*Math.PI/180, M=200, dense=[]; var thick=function(s){return tMax*Math.pow(s,0.62);}; var k,s,ang,ro,ri; for(k=0;k<=M;k++){ s=k/M; ang=-sweep/2+sweep*s; ro=R+thick(s)/2; dense.push({x:ro*Math.cos(ang),y:ro*Math.sin(ang)}); } var ang1=sweep/2, rad={x:Math.cos(ang1),y:Math.sin(ang1)}, tan={x:-Math.sin(ang1),y:Math.cos(ang1)}, Cc={x:R*Math.cos(ang1),y:R*Math.sin(ang1)}, cr=tMax/2, CAP=26; for(k=1;k<CAP;k++){ var phi=Math.PI*k/CAP; dense.push({x:Cc.x+cr*(Math.cos(phi)*rad.x+Math.sin(phi)*tan.x),y:Cc.y+cr*(Math.cos(phi)*rad.y+Math.sin(phi)*tan.y)}); } for(k=M;k>=0;k--){ s=k/M; ang=-sweep/2+sweep*s; ri=R-thick(s)/2; dense.push({x:ri*Math.cos(ang),y:ri*Math.sin(ang)}); } var res=resample(dense,n); arcSign=signedArea(res); return res.map(function(pt){ return {rad:Math.hypot(pt.x,pt.y),ang:Math.atan2(pt.y,pt.x)}; }); }
  function alignOffsets(){ if(!pieces.length||!arc.length) return; var D=Math.PI/180; for(var pi=0;pi<pieces.length;pi++){ var pc=pieces[pi]; var base=pc.slot*D; var tx=new Float64Array(N), ty=new Float64Array(N), i; for(i=0;i<N;i++){ var a=base+arc[i].ang; tx[i]=Cx+arc[i].rad*Math.cos(a); ty[i]=Cy+arc[i].rad*Math.sin(a); } var best=0, bestErr=Infinity, o; for(o=0;o<N;o++){ var err=0; for(var kk=0;kk<N;kk+=4){ var sp=pc.src[kk]; var jj=(kk+o)%N; var dx=sp.x-tx[jj], dy=sp.y-ty[jj]; err+=dx*dx+dy*dy; if(err>=bestErr) break; } if(err<bestErr){ bestErr=err; best=o; } } pc.offset=best; } }
  function ease(p){ p=Math.max(0,Math.min(1,p)); return p*p*p*(p*(p*6-15)+10); }
  function loop(){ var now=performance.now(); var R=ringRadius, sweep=arcSweep, tMax=thickness; var key=R+'|'+sweep+'|'+tMax; if(key!==arcKey){ arc=buildArc(R,sweep,tMax,N); arcKey=key; alignOffsets(); } var T=cycle/speed; var phase=(now%T)/T; var hold0=hold, n=pieces.length, ramp0=ramp; var span=Math.max(0.05,(1-2*hold0)/2); var downStart=hold0, circStart=downStart+span, upStart=circStart+hold0; var spin=360*turns*phase; var D=Math.PI/180; for(var pi=0;pi<pieces.length;pi++){ var pc=pieces[pi]; var m=pc.order; var outAt=downStart+(m/n)*(span-ramp0); var inAt=upStart+(m/n)*(span-ramp0); var ep; if(phase<outAt) ep=0; else if(phase<outAt+ramp0) ep=ease((phase-outAt)/ramp0); else if(phase<inAt) ep=1; else if(phase<inAt+ramp0) ep=ease(1-(phase-inAt)/ramp0); else ep=0; var midAng=(pc.slot+spin)*D; var off=pc.offset||0; var d='M'; for(var k=0;k<N;k++){ var ai=(k+off)%N; var rr=arc[ai].rad; var ar=midAng+arc[ai].ang; var hp=pc.srcPolar[k]; var r=hp.r+(rr-hp.r)*ep; var dA=ar-hp.a; dA=Math.atan2(Math.sin(dA),Math.cos(dA)); var a=hp.a+dA*ep; var x=Cx+r*Math.cos(a); var y=Cy+r*Math.sin(a); d+=(k?'L':'')+x.toFixed(2)+' '+y.toFixed(2); } d+='Z'; pc.path.setAttribute('d',d); } raf=requestAnimationFrame(loop); }
  function start(){ var pathEls=Array.prototype.slice.call(svg.querySelectorAll('.pc')); if(!pathEls.length||!pathEls[0].getTotalLength){ raf=requestAnimationFrame(start); return; } buildArc(30,30,11,N); var targetSign=arcSign; pieces=pathEls.map(function(path){ var L=path.getTotalLength(); var src=[]; for(var j=0;j<N;j++){ var pt=path.getPointAtLength(L*j/N); src.push({x:pt.x,y:pt.y}); } if(Math.sign(signedArea(src))!==Math.sign(targetSign)) src.reverse(); return {path:path,src:src}; }); var gx=0,gy=0,gc=0,pi,p; for(pi=0;pi<pieces.length;pi++){ for(var si=0;si<pieces[pi].src.length;si++){ p=pieces[pi].src[si]; gx+=p.x; gy+=p.y; gc++; } } Cx=gx/gc; Cy=gy/gc; for(pi=0;pi<pieces.length;pi++){ var pc=pieces[pi]; var sx=0,sy=0; for(var sj=0;sj<pc.src.length;sj++){ sx+=pc.src[sj].x; sy+=pc.src[sj].y; } pc.cx=sx/pc.src.length; pc.cy=sy/pc.src.length; pc.rad=Math.hypot(pc.cx-Cx,pc.cy-Cy); pc.ang=Math.atan2(pc.cy-Cy,pc.cx-Cx)*180/Math.PI; pc.cw=(((pc.ang+90)%360)+360)%360; } var byAngle=pieces.slice().sort(function(a,b){return a.cw-b.cw;}); var centerPiece=pieces.reduce(function(mm,pc){return pc.rad<mm.rad?pc:mm;},pieces[0]); var peel=byAngle.filter(function(pc){return pc!==centerPiece;}).concat([centerPiece]); var nn=peel.length, step=360/nn; peel.forEach(function(pc,m){ pc.order=m; pc.sigma=m/nn; pc.slot=-90+m*step; }); for(pi=0;pi<pieces.length;pi++){ var pc2=pieces[pi]; pc2.srcPolar=pc2.src.map(function(p){ return {r:Math.hypot(p.x-Cx,p.y-Cy),a:Math.atan2(p.y-Cy,p.x-Cx)}; }); } loop(); }
  start();
  return function(){ if(raf) cancelAnimationFrame(raf); };
};`;
