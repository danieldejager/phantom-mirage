import math,numpy as np
from PIL import Image, ImageDraw, ImageFont
G="/usr/share/fonts/truetype/sand-box/google/"
MONO=G+"JetBrains Mono/JetBrainsMono-VariableFont_wght.ttf"
AL=G+"Aldrich/Aldrich-Regular.ttf"
m=np.load("logo_masks.npz"); shape=m["shape"]; dark=m["dark"]
ys,xs=np.where(shape>0.5); y0,y1,x0,x1=ys.min()-6,ys.max()+6,xs.min()-6,xs.max()+6
shape=shape[y0:y1,x0:x1]; dark=dark[y0:y1,x0:x1]
W,H=1920,1080; S=2
def hx(c): return np.array([int(c[i:i+2],16) for i in (1,3,5)],float)
def logo_rgba(width,c_dark,c_mid):
    h=int(width*shape.shape[0]/shape.shape[1])
    col=c_mid[None,None,:]*(1-dark[...,None])+c_dark[None,None,:]*dark[...,None]
    rgb=Image.fromarray(col.astype("uint8")).resize((width,h),Image.LANCZOS)
    a=Image.fromarray((shape*255).astype("uint8")).resize((width,h),Image.LANCZOS)
    rgb.putalpha(a); return rgb
def track(d,text,font,cx,y,fill,sp):
    tw=sum(d.textlength(c,font=font)+sp for c in text)-sp
    x=cx-tw/2
    for c in text:
        d.text((x,y),c,font=font,fill=fill); x+=d.textlength(c,font=font)+sp
def spinner(im,cx,cy,rad,phase,col,n=36):
    d=ImageDraw.Draw(im,"RGBA")
    for i in range(n):
        a=2*math.pi*i/n-math.pi/2; t=((i-phase)%n)/n
        al=min(255,int(255*(1-t)**2.2)+22)
        d.line([(cx+rad*0.62*math.cos(a),cy+rad*0.62*math.sin(a)),(cx+rad*math.cos(a),cy+rad*math.sin(a))],fill=tuple(col)+(al,),width=int(3.4*S))
def build(theme,status,detail,fn,phase):
    if theme=="light":
        bg=hx("#E9ECEF"); cd=hx("#2E2E32"); cm=hx("#5C5C60"); txt=(70,72,78); mut=(112,116,124); sp=(60,62,68); glow=hx("#FFFFFF")
    else:
        bg=hx("#0B0C0F"); cd=hx("#EEF0F3"); cm=hx("#8A909A"); txt=(205,208,214); mut=(120,125,134); sp=(235,238,242); glow=hx("#1B1D24")
    y,x=np.mgrid[0:H*S,0:W*S].astype(float)
    r=np.sqrt(((x-W*S/2)/(W*S*0.55))**2+((y-H*S*0.42)/(H*S*0.6))**2)
    g=np.clip(1-r,0,1)**2
    arr=bg[None,None,:]+(glow-bg)[None,None,:]*g[...,None]*0.9
    im=Image.fromarray(np.clip(arr,0,255).astype("uint8"))
    lg=logo_rgba(780*S,cd,cm)
    im.paste(lg,(int(W*S/2-lg.width/2),int(215*S)),lg)
    d=ImageDraw.Draw(im,"RGBA")
    ly=int(215*S)+lg.height
    spinner(im,W*S/2,(ly+120*S),34*S,phase,sp)
    d=ImageDraw.Draw(im,"RGBA")
    track(d,status,ImageFont.truetype(AL,22*S),W*S/2,ly+190*S,txt,5*S)
    f=ImageFont.truetype(MONO,17*S); d.text((W*S/2-d.textlength(detail,font=f)/2,ly+236*S),detail,font=f,fill=mut)
    track(d,"PHANTOM TECHNOLOGIES PTY LTD",ImageFont.truetype(AL,21*S),W*S/2,985*S,txt,6*S)
    track(d,"\u00a9 2026 PHANTOM TECHNOLOGIES PTY LTD. ALL RIGHTS RESERVED.",ImageFont.truetype(AL,13*S),W*S/2,1030*S,mut,3*S)
    im.resize((W,H),Image.LANCZOS).save(fn)
for th in ("light","dark"):
    build(th,"STARTING SENSOR","integrity check passed  |  loading decoy engine",f"splash_{th}_boot.png",28)
    build(th,"SHUTTING DOWN SECURELY","closing sessions  |  flushing logs  |  sealing storage",f"splash_{th}_shutdown.png",14)
