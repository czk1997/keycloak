"use strict";(self.webpackChunkkew_shadow=self.webpackChunkkew_shadow||[]).push([[575],{575:(e,s,a)=>{a.r(s),a.d(s,{default:()=>Z});var l=a(2791),t=a(969),i=a(7107),r=a(8777),n=a(9207),o=a(3478),d=a(532),c=a(5824),m=a(9683),x=a(8323),u=a(7577),p=a(8617),f=a(113),j=a(7617),w=a(2180),h=a(2553),g=a(1030),v=a(3761),b=a(7680),N=a(5037),y=a(6509),k=a(184);const C=new URL(window.location.href).searchParams.get("my_custom_param");null!==C&&console.log("my_custom_param:",C);const I={microsoft:(0,k.jsx)(m.Z,{}),google:(0,k.jsx)(x.Z,{}),facebook:(0,k.jsx)(u.Z,{}),twitter:(0,k.jsx)(p.Z,{}),stackoverflow:(0,k.jsx)(f.Z,{}),gitlab:(0,k.jsx)(j.Z,{}),paypal:(0,k.jsx)(w.Z,{}),instagram:(0,k.jsx)(h.Z,{}),linkedin:(0,k.jsx)(g.Z,{}),github:(0,k.jsx)(v.Z,{}),bitbucket:(0,k.jsx)(b.Z,{}),openshift:(0,k.jsx)(N.Z,{})};function Z(e){const{kcContext:s,i18n:a,doUseDefaultCss:m,Template:x,classes:u}=e,{getClassName:p}=(0,i.v)({doUseDefaultCss:m,classes:u}),{social:f,realm:j,url:w,usernameHidden:h,login:g,auth:v,registrationDisabled:b}=s,{msg:N,msgStr:C}=a;(0,y.Z)(a.msgStr("loginTitle",s.realm.displayName));const[Z,U]=(0,l.useState)(!1),_=(0,t.O)((e=>{var s;e.preventDefault(),U(!0);const a=e.target;null===(s=a.querySelector("input[name='email']"))||void 0===s||s.setAttribute("name","username"),a.submit()}));return(0,k.jsx)(x,{kcContext:s,i18n:a,doUseDefaultCss:m,classes:u,displayInfo:f.displayInfo,displayWide:j.password&&void 0!==f.providers,headerNode:N("doLogIn"),infoNode:j.password&&j.registrationAllowed&&!b&&(0,k.jsxs)("div",{id:"kc-registration",className:"justify-center items-center text-center mb-3 w-full",children:[(0,k.jsx)(c.Z,{className:"mb-1 mt-1"}),(0,k.jsxs)("span",{className:"text-slate-500 text-sm",children:[N("noAccount")," "," ",(0,k.jsx)("a",{tabIndex:6,href:w.registrationUrl,className:"text-slate-950",children:N("doRegister")})]})]}),children:(0,k.jsxs)("div",{className:"flex gap-4",children:[(0,k.jsx)("div",{className:"mx-auto flex w-full flex-col justify-center",id:"kc-form-wrapper",children:j.password&&(0,k.jsxs)("form",{id:"kc-form-login",onSubmit:_,action:w.loginAction,method:"post",className:"flex flex-col gap-3 items-center w-full min-w-[350px]",children:[(0,k.jsx)("div",{className:"w-full flex flex-col items-center justify-center",children:!h&&(e=>{const s=j.loginWithEmailAllowed?j.registrationEmailAsUsername?"email":"usernameOrEmail":"username",a="usernameOrEmail"===s?"username":s;return(0,k.jsxs)("div",{className:"grid w-full max-w-sm items-center gap-1.5",children:[(0,k.jsxs)(d._,{htmlFor:"autoCompleteHelper",children:[" ",N(s)]}),(0,k.jsx)(r.I,{tabIndex:1,id:a,className:p("kcInputClass"),name:a,defaultValue:null!==(e=g.username)&&void 0!==e?e:"",type:"text",autoFocus:!0,autoComplete:"off"})]})})()}),(0,k.jsxs)("div",{className:"w-full flex flex-col items-center justify-center",children:[(0,k.jsxs)("div",{className:"grid w-full max-w-sm items-center gap-1.5",children:[(0,k.jsx)(d._,{htmlFor:"password",children:N("password")}),(0,k.jsx)(r.I,{tabIndex:2,id:"password",name:"password",type:"password",autoComplete:"off"})]}),j.resetPasswordAllowed&&(0,k.jsx)("span",{className:"text-sm mt-1 w-full text-slate-500 w-full text-center items-start flex justify-start",children:(0,k.jsx)("a",{tabIndex:5,href:w.loginResetCredentialsUrl,children:N("doForgotPassword")})})]}),(0,k.jsx)("div",{className:"w-full flex flex-col items-center justify-center",children:(0,k.jsx)("div",{id:"kc-form-options",children:j.rememberMe&&!h&&(0,k.jsxs)("div",{className:"flex items-center space-x-2",children:[(0,k.jsx)(o.X,{id:"terms2",defaultChecked:"on"===g.rememberMe}),(0,k.jsx)("label",{htmlFor:"terms2",className:"text-sm font-medium leading-none peer-disabled:cursor-not-allowed peer-disabled:opacity-70",children:N("rememberMe")})]})})}),(0,k.jsx)("input",{type:"hidden",id:"id-hidden-input",name:"credentialId",...void 0!==(null===v||void 0===v?void 0:v.selectedCredential)?{value:v.selectedCredential}:{}}),(0,k.jsx)(n.z,{tabIndex:4,name:"login",id:"kc-login",type:"submit",className:"min-w-[200px]",disabled:Z,children:C("doLogIn")})]})}),j.password&&void 0!==f.providers&&(0,k.jsxs)("div",{id:"kc-social-providers",className:"flex gap-4 w-auto",children:[(0,k.jsx)(c.Z,{orientation:"vertical"}),(0,k.jsx)("div",{className:"grid flex-col flex-wrap grid-cols-2 gap-2 w-[320px]",children:f.providers.map((e=>(0,k.jsxs)(n.z,{onClick:()=>window.location.href=e.loginUrl,id:"zocial-".concat(e.alias),className:"".concat((0,n.d)({variant:"secondary"})," w-[160px] flex justify-start gap-2"),children:[I[e.providerId],(0,k.jsx)("span",{children:e.displayName})]},e.providerId)))})]})]})})}}}]);
//# sourceMappingURL=575.93896171.chunk.js.map