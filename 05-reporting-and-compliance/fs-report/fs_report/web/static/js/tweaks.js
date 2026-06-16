/* ============================================================
   Shared Tweaks controller. Injects the panel + a floating
   launcher, wires the host edit-mode protocol, applies tweaks
   to :root / body, and persists to localStorage 'fs_tweaks_v1'
   (shared across every Phase 2 screen). Load AFTER lucide and
   after the page's own scripts (place before </body>).
   ============================================================ */
(function(){
  /* Each accent: dark value (c/rgb) + optional light variant (light/lightRgb)
     for readability on the light theme's pale background. Mint's light variant
     is the teal the light theme used as its hardcoded default, so the default
     light look is unchanged; cyan/violet/orange read fine on light as-is. */
  var ACC={
    mint:{c:'#5EEAD4',rgb:'94,234,212',light:'#0D9488',lightRgb:'13,148,136'},
    cyan:{c:'#22D3EE',rgb:'34,211,238'},
    violet:{c:'#A78BFA',rgb:'167,139,250'},
    orange:{c:'#F27229',rgb:'242,114,41'}
  };
  var DEF={accent:'mint',glow:'subtle',density:'regular',motion:true,backdrop:true,theme:'dark'};
  var T=Object.assign({},DEF,(function(){try{return JSON.parse(localStorage.getItem('fs_tweaks_v1'))||{}}catch(e){return{}}})());

  var fab=document.createElement('div');
  fab.className='tw-fab';fab.title='Tweaks';
  /* B13 #16: an appearance glyph (palette). The old slider icon read as
     settings/filters, confusable with Settings. Tweaks = theme/appearance. */
  fab.innerHTML='<i data-lucide="palette"></i>';

  var panel=document.createElement('aside');
  panel.className='tweaks';panel.id='tweaks';
  panel.innerHTML=''+
    '<div class="tw-head"><span class="tt"><i data-lucide="palette"></i> Tweaks</span><span class="tx" id="tw-close"><i data-lucide="x"></i></span></div>'+
    '<div class="tw-body">'+
      '<div class="tw-sec"><div class="tw-tog"><span class="tl">Light mode</span><span class="tw-sw2" id="tw-theme"></span></div></div>'+
      '<div class="tw-sec"><span class="tw-lbl">Accent</span><div class="tw-swatches" id="tw-accent">'+
        '<span class="tw-sw" data-acc="mint" style="background:#5EEAD4;color:#5EEAD4" title="Mint"></span>'+
        '<span class="tw-sw" data-acc="cyan" style="background:#22D3EE;color:#22D3EE" title="Cyan"></span>'+
        '<span class="tw-sw" data-acc="violet" style="background:#A78BFA;color:#A78BFA" title="Violet"></span>'+
        '<span class="tw-sw" data-acc="orange" style="background:#F27229;color:#F27229" title="Forge Orange"></span>'+
      '</div></div>'+
      '<div class="tw-sec"><span class="tw-lbl">Glow intensity</span><div class="tw-seg" id="tw-glow">'+
        '<button data-glow="flat">Flat</button><button data-glow="subtle">Subtle</button><button data-glow="cinematic">Cinematic</button></div></div>'+
      '<div class="tw-sec"><span class="tw-lbl">Density</span><div class="tw-seg" id="tw-density">'+
        '<button data-den="calm">Calm</button><button data-den="regular">Regular</button><button data-den="cockpit">Cockpit</button></div></div>'+
      '<div class="tw-sec"><div class="tw-tog"><span class="tl">Motion</span><span class="tw-sw2" id="tw-motion"></span></div></div>'+
      '<div class="tw-sec"><div class="tw-tog"><span class="tl">Deep-space backdrop</span><span class="tw-sw2" id="tw-backdrop"></span></div></div>'+
    '</div>'+
    '<div class="tw-foot">Persists across all Phase 2 screens.</div>';

  var _bar=document.querySelector('.topbar');if(_bar){fab.classList.add('in-bar');_bar.appendChild(fab);}else{document.body.appendChild(fab);}
  document.body.appendChild(panel);
  if(window.lucide)lucide.createIcons();

  function sync(){
    panel.querySelectorAll('#tw-accent .tw-sw').forEach(function(s){s.classList.toggle('on',s.dataset.acc===T.accent);});
    panel.querySelectorAll('#tw-glow button').forEach(function(x){x.classList.toggle('on',x.dataset.glow===T.glow);});
    panel.querySelectorAll('#tw-density button').forEach(function(x){x.classList.toggle('on',x.dataset.den===T.density);});
    panel.querySelector('#tw-motion').classList.toggle('on',T.motion);
    panel.querySelector('#tw-backdrop').classList.toggle('on',T.backdrop);
    panel.querySelector('#tw-theme').classList.toggle('on',T.theme==='light');
  }
  function apply(){
    var r=document.documentElement,b=document.body,a=ACC[T.accent]||ACC.mint;
    /* Light mode uses the accent's light variant (where defined) for contrast on
       the pale background. Set the custom props on <body> as well as <html>: the
       light theme's `body.light{--accent}` rule lives on <body> and would
       otherwise shadow a value set only on <html>, so an INLINE prop on <body>
       (which beats any stylesheet rule on the same element) is what makes the
       accent picker actually take effect in light mode — not just dark. */
    var light=(T.theme==='light');
    var col=(light&&a.light)?a.light:a.c,rgb=(light&&a.lightRgb)?a.lightRgb:a.rgb;
    [r,b].forEach(function(el){
      el.style.setProperty('--accent',col);
      el.style.setProperty('--accent-rgb',rgb);
      el.style.setProperty('--accent-grad-end',col);
    });
    b.classList.toggle('glow-flat',T.glow==='flat');b.classList.toggle('glow-cinematic',T.glow==='cinematic');
    b.classList.toggle('density-calm',T.density==='calm');b.classList.toggle('density-cockpit',T.density==='cockpit');
    b.classList.toggle('no-motion',!T.motion);b.classList.toggle('no-backdrop',!T.backdrop);b.classList.toggle('light',T.theme==='light');
    try{document.documentElement.setAttribute('data-theme',T.theme);localStorage.setItem('fs-theme',T.theme);}catch(e){}
    sync();
  }
  function set(k,v){T[k]=v;try{localStorage.setItem('fs_tweaks_v1',JSON.stringify(T));}catch(e){}
    if(k==='theme'){try{document.documentElement.setAttribute('data-theme',v);localStorage.setItem('fs-theme',v);}catch(e){}}
    apply();try{window.parent.postMessage({type:'__edit_mode_set_keys',edits:(function(){var o={};o[k]=v;return o;})()},'*');}catch(e){}}

  apply();

  panel.querySelectorAll('#tw-accent .tw-sw').forEach(function(s){s.onclick=function(){set('accent',s.dataset.acc);};});
  panel.querySelectorAll('#tw-glow button').forEach(function(x){x.onclick=function(){set('glow',x.dataset.glow);};});
  panel.querySelectorAll('#tw-density button').forEach(function(x){x.onclick=function(){set('density',x.dataset.den);};});
  panel.querySelector('#tw-motion').onclick=function(){set('motion',!T.motion);};
  panel.querySelector('#tw-backdrop').onclick=function(){set('backdrop',!T.backdrop);};
  panel.querySelector('#tw-theme').onclick=function(){set('theme',T.theme==='light'?'dark':'light');};

  fab.onclick=function(){panel.classList.toggle('open');};
  panel.querySelector('#tw-close').onclick=function(){panel.classList.remove('open');try{window.parent.postMessage({type:'__edit_mode_dismissed'},'*');}catch(e){}};
  window.addEventListener('message',function(e){var t=e&&e.data&&e.data.type;if(t==='__activate_edit_mode')panel.classList.add('open');else if(t==='__deactivate_edit_mode')panel.classList.remove('open');});
  try{window.parent.postMessage({type:'__edit_mode_available'},'*');}catch(e){}
})();
