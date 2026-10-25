from PIL import Image, ImageFilter
import numpy as np
SC=6
ref=Image.open("logo_ref.png").convert("RGB")
# crop out the card border/rounded corners: keep the logo area only
box=(20,8,300,128)
ref=ref.crop(box)
L=np.array(ref.convert("L")).astype(float)
bg=232.0
big=Image.fromarray(L.astype("uint8")).resize((ref.width*SC,ref.height*SC),Image.BICUBIC).filter(ImageFilter.GaussianBlur(SC*0.45))
B=np.array(big).astype(float)
def smooth(x,lo,hi):
    t=np.clip((x-lo)/(hi-lo),0,1); return t*t*(3-2*t)
# silhouette (anything darker than halfway between bg and mid tone)
shape=1-smooth(B,150,172)
# dark front-P: core darker than ~ halfway between dark and mid tone, biased to cover the edge halo
dark=1-smooth(B,76,92)
# the halo around dark edges against bg reads as mid; extend dark by a dilation limited to pixels next to bg
dk=Image.fromarray((dark*255).astype("uint8")).filter(ImageFilter.MaxFilter(2*SC//2+1))
dk=np.array(dk).astype(float)/255
# only apply dilation where the neighbouring pixels toward bg (B>200 within radius) exist
near_bg=np.array(Image.fromarray((B>205).astype("uint8")*255).filter(ImageFilter.MaxFilter(SC*2+1))).astype(float)/255
dark_final=np.where(near_bg>0.5,np.maximum(dark,dk),dark)
dark_final=np.clip(dark_final,0,1)*shape
out=dict(shape=shape,dark=dark_final)
np.savez("logo_masks.npz",**out)
print(shape.shape)
# preview in original colours
pv=np.zeros(shape.shape+(3,))+232
mid=np.array([92,92,96.]);drk=np.array([46,46,50.])
col=mid[None,None,:]*(1-dark_final[...,None])+drk[None,None,:]*dark_final[...,None]
pv=pv*(1-shape[...,None])+col*shape[...,None]
Image.fromarray(pv.astype("uint8")).save("logo_clean_light.png")
