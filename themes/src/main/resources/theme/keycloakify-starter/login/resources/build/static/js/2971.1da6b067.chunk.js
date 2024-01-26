"use strict";(self.webpackChunkkew_shadow=self.webpackChunkkew_shadow||[]).push([[2971],{2971:(e,s,a)=>{a.r(s),a.d(s,{default:()=>x});var t=a(2791),r=a(2828);const{useI18n:n}=(0,r.createUseI18n)({});var c=a(6055),l=a(7747),i=a(1652),o=a(8258),d=a(184);function u(e){const{kcContext:s,i18n:a,doUseDefaultCss:t,active:r,classes:n,children:u}=e,{getClassName:h}=(0,i.v)({doUseDefaultCss:t,classes:n}),{msg:p,changeLocale:m,labelBySupportedLanguageTag:f,currentLanguageTag:v}=a,{locale:x,url:j,features:y,realm:g,message:C,referrer:N}=s,{isReady:k}=(0,l.M)({doFetchDefaultThemeResources:t,styles:["".concat(j.resourcesCommonPath,"/node_modules/patternfly/dist/css/patternfly.min.css"),"".concat(j.resourcesCommonPath,"/node_modules/patternfly/dist/css/patternfly-additions.min.css"),"".concat(j.resourcesPath,"/css/account.css")],htmlClassName:h("kcHtmlClass"),bodyClassName:(0,c.W)("admin-console","user",h("kcBodyClass"))});return k?(0,d.jsxs)(d.Fragment,{children:[(0,d.jsx)("header",{className:"navbar navbar-default navbar-pf navbar-main header",children:(0,d.jsxs)("nav",{className:"navbar",role:"navigation",children:[(0,d.jsx)("div",{className:"navbar-header",children:(0,d.jsx)("div",{className:"container",children:(0,d.jsx)("h1",{className:"navbar-title",children:"Keycloak"})})}),(0,d.jsx)("div",{className:"navbar-collapse navbar-collapse-1",children:(0,d.jsx)("div",{className:"container",children:(0,d.jsxs)("ul",{className:"nav navbar-nav navbar-utility",children:[g.internationalizationEnabled&&((0,o.h)(void 0!==x),!0)&&x.supported.length>1&&(0,d.jsx)("li",{children:(0,d.jsxs)("div",{className:"kc-dropdown",id:"kc-locale-dropdown",children:[(0,d.jsx)("a",{href:"#",id:"kc-current-locale-link",children:f[v]}),(0,d.jsx)("ul",{children:x.supported.map((e=>{let{languageTag:s}=e;return(0,d.jsx)("li",{className:"kc-dropdown-item",children:(0,d.jsx)("a",{href:"#",onClick:()=>m(s),children:f[s]})},s)}))})]})}),(null===N||void 0===N?void 0:N.url)&&(0,d.jsx)("li",{children:(0,d.jsx)("a",{href:N.url,id:"referrer",children:p("backTo",N.name)})}),(0,d.jsx)("li",{children:(0,d.jsx)("a",{href:j.getLogoutUrl(),children:p("doSignOut")})})]})})})]})}),(0,d.jsxs)("div",{className:"container",children:[(0,d.jsx)("div",{className:"bs-sidebar col-sm-3",children:(0,d.jsxs)("ul",{children:[(0,d.jsx)("li",{className:(0,c.W)("account"===r&&"active"),children:(0,d.jsx)("a",{href:j.accountUrl,children:p("account")})}),y.passwordUpdateSupported&&(0,d.jsx)("li",{className:(0,c.W)("password"===r&&"active"),children:(0,d.jsx)("a",{href:j.passwordUrl,children:p("password")})}),(0,d.jsx)("li",{className:(0,c.W)("totp"===r&&"active"),children:(0,d.jsx)("a",{href:j.totpUrl,children:p("authenticator")})}),y.identityFederation&&(0,d.jsx)("li",{className:(0,c.W)("social"===r&&"active"),children:(0,d.jsx)("a",{href:j.socialUrl,children:p("federatedIdentity")})}),(0,d.jsx)("li",{className:(0,c.W)("sessions"===r&&"active"),children:(0,d.jsx)("a",{href:j.sessionsUrl,children:p("sessions")})}),(0,d.jsx)("li",{className:(0,c.W)("applications"===r&&"active"),children:(0,d.jsx)("a",{href:j.applicationsUrl,children:p("applications")})}),y.log&&(0,d.jsx)("li",{className:(0,c.W)("log"===r&&"active"),children:(0,d.jsx)("a",{href:j.logUrl,children:p("log")})}),g.userManagedAccessAllowed&&y.authorization&&(0,d.jsx)("li",{className:(0,c.W)("authorization"===r&&"active"),children:(0,d.jsx)("a",{href:j.resourceUrl,children:p("myResources")})})]})}),(0,d.jsxs)("div",{className:"col-sm-9 content-area",children:[void 0!==C&&(0,d.jsxs)("div",{className:(0,c.W)("alert","alert-".concat(C.type)),children:["success"===C.type&&(0,d.jsx)("span",{className:"pficon pficon-ok"}),"error"===C.type&&(0,d.jsx)("span",{className:"pficon pficon-error-circle-o"}),(0,d.jsx)("span",{className:"kc-feedback-text",children:C.summary})]}),u]})]})]}):null}const h=(0,t.lazy)((()=>a.e(716).then(a.bind(a,716)))),p=(0,t.lazy)((()=>a.e(7047).then(a.bind(a,7047)))),m=(0,t.lazy)((()=>a.e(8959).then(a.bind(a,8959)))),f=(0,t.lazy)((()=>Promise.resolve().then(a.bind(a,2828)))),v={kcBodyClass:"my-root-account-class"};function x(e){const{kcContext:s}=e,a=n({kcContext:s});return null===a?null:(0,d.jsx)(t.Suspense,{children:(()=>{switch(s.pageId){case"password.ftl":return(0,d.jsx)(h,{kcContext:s,i18n:a,Template:u,classes:v,doUseDefaultCss:!0});case"my-extra-page-1.ftl":return(0,d.jsx)(p,{kcContext:s,i18n:a,Template:u,classes:v,doUseDefaultCss:!0});case"my-extra-page-2.ftl":return(0,d.jsx)(m,{kcContext:s,i18n:a,Template:u,classes:v,doUseDefaultCss:!0});default:return(0,d.jsx)(f,{kcContext:s,i18n:a,classes:v,Template:u,doUseDefaultCss:!0})}})()})}},1652:(e,s,a)=>{a.d(s,{v:()=>r});var t=a(2889);const{useGetClassName:r}=(0,t.a)({defaultClasses:{kcHtmlClass:void 0,kcBodyClass:void 0,kcButtonClass:"btn",kcButtonPrimaryClass:"btn-primary",kcButtonLargeClass:"btn-lg",kcButtonDefaultClass:"btn-default"}})},2889:(e,s,a)=>{a.d(s,{a:()=>n});var t=a(6055),r=a(969);function n(e){const{defaultClasses:s}=e;return{useGetClassName:function(e){const{classes:a}=e;return{getClassName:(0,r.O)((e=>(0,t.W)(e,s[e],null===a||void 0===a?void 0:a[e])))}}}}},7747:(e,s,a)=>{a.d(s,{M:()=>c});var t=a(2791),r=a(1630),n=a(6055);function c(e){const{doFetchDefaultThemeResources:s,styles:a=[],scripts:n=[],htmlClassName:c,bodyClassName:i}=e,[o,d]=(0,t.useReducer)((()=>!0),!s);return(0,t.useEffect)((()=>{if(!s)return;let e=!1;const t=[];return(async()=>{for(const s of[...a].reverse()){const{prLoaded:a,remove:n}=(0,r.t)({type:"css",position:"prepend",href:s});if(t.push(n),await a,e)return}d()})(),n.forEach((e=>{const{remove:s}=(0,r.t)({type:"javascript",src:e});t.push(s)})),()=>{e=!0,t.forEach((e=>e()))}}),[]),l({target:"html",className:c}),l({target:"body",className:i}),{isReady:o}}function l(e){const{target:s,className:a}=e;(0,t.useEffect)((()=>{if(void 0===a)return;const e=document.getElementsByTagName(s)[0].classList,t=(0,n.W)(a).split(" ");return e.add(...t),()=>{e.remove(...t)}}),[a])}},4943:()=>{HTMLElement.prototype.prepend||(HTMLElement.prototype.prepend=function(e){if("string"===typeof e)throw new Error("Error with HTMLElement.prototype.appendFirst polyfill");this.insertBefore(e,this.firstChild)})},8258:(e,s,a)=>{a.d(s,{h:()=>t.h});var t=a(9883)},6055:(e,s,a)=>{a.d(s,{W:()=>n});var t=a(9883),r=a(9465);const n=function(){const e=arguments.length;let s=0,a="";for(;s<e;s++){const e=s<0||arguments.length<=s?void 0:arguments[s];if(null==e)continue;let c;switch(typeof e){case"boolean":break;case"object":if(Array.isArray(e))c=n(...e);else{(0,t.h)(!(0,r.z)(e,!1)),c="";for(const s in e)e[s]&&s&&(c&&(c+=" "),c+=s)}break;default:c=e}c&&(a&&(a+=" "),a+=c)}return a}},1630:(e,s,a)=>{a.d(s,{t:()=>r});a(4943);var t=a(3172);function r(e){const s=document.createElement((()=>{switch(e.type){case"css":return"link";case"javascript":return"script"}})()),a=new t.Deferred;return s.addEventListener("load",(()=>a.resolve())),Object.assign(s,(()=>{switch(e.type){case"css":return{href:e.href,type:"text/css",rel:"stylesheet",media:"screen,print"};case"javascript":return{src:e.src,type:"text/javascript"}}})()),document.getElementsByTagName("head")[0][(()=>{switch(e.type){case"javascript":return"appendChild";case"css":return(()=>{switch(e.position){case"append":return"appendChild";case"prepend":return"prepend"}})()}})()](s),{prLoaded:a.pr,remove:()=>s.remove()}}},9465:(e,s,a)=>{function t(e,s){return s}a.d(s,{z:()=>t})}}]);
//# sourceMappingURL=2971.1da6b067.chunk.js.map