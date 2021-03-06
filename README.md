# DLNAmpvRenderer

A script in Python 3 to turn mpv into a DLNA/UPnP renderer

DLNAmpvRenderer is an application written in Python 3 designed as a wrapper for mpv to use the player as a DLNA/UPnP renderer, on a computer running under Windows. The script does not need any other package, only the presence of an executable of mpv is required. The application has been tested with a few DLNA controlers (Windows Media Player Digital Media Controller, Bubble UPnP, UPnPlay, DLNAPlayOn) but should work with any DLNA compliant controler. Subtitles management is enabled through the DIDL description ('subtitlefileuri' or 'captioninfo'/'captioninfoex' tags) or the use of a 'captioninfo.sec' header in the response to the HEAD/GET request for the content to be played. Several instances can run in parallel provided they use different ports and names.

To install the application:

- of course, install Python 3
- copy DLNAmpvRenderer.py, icon.png and mpv.bat in the same folder
- install mpv (https://mpv.io/installation/ or, for the bravest, https://github.com/m-ab-s/media-autobuild_suite)
- open mpv.bat and, if needed, change the path of mpv executable (more customization can be made later on)
- allow mpv and python to communicate through the firewall (for more precise needs, see below)

To run the application:

 DLNAmpvRenderer -h to display the complete syntax of command line and abbreviated commands
    
 DLNAmpvRenderer [-h] [--port RENDERER_TCP_PORT] [--name RENDERER_NAME] [--minimize] [--fullscreen] [--rotate_jpeg] [--wmpdmc_no_mkv] [--trust_controler] [--search_subtitles] [--verbosity VERBOSE]  
    
  --port RENDERER_TCP_PORT: the port used by the renderer on the local machine sent to the controlers in the advertisements and the answers to the search requests    
  --name RENDERER_NAME: the name of the renderer, used to generate the uuid    
  --minimize: when set, minimizes the window of mpv when inactive and restore it to its previous size when a playback is launched (useful when displaying photos as some controlers stop the playback between two consecutive pictures or when playing music as there is no use showing the window)    
  --fullscreen: when set, makes mpv go fullscreen each time a playback starts (can be combined with 'minimize')    
  --rotate_jpeg: when set, tries to read the orientation metadata of jpeg pictures, and send an accordingly rotation command to mpv, to make up for the inability of the player (due to ffmpeg) to do so by itself (the day when ffmpeg manages EXIF orientation for pictures, it will no longer be needed)    
  --wmpdmc_no_mkv: when set, Windows Media Player Digital Media Controller will transcode 'mkv' (matroska) files to 'mpegts' before streaming the content, allowing remote control of the playback, otherwise, the 'mkv' file will be streamed as it is, and the seekbar will probably be inactive in WMPDMC (but available in mpv)    
  --trust_controler: when set, the URL of the content sent to the renderer is not checked before being passed to mpv, which will not work if the server throws errors at range requests (as some DLNA servers do)    
  --search_subtitles: when set, always requests subtitles, trying different extensions if no subtitle uri is provided by the controler or the server (may slow down the process)     
  --verbosity VERBOSE: for troubleshooting purposes, from 0 (default) to 2  

 Example: DLNAmpvRenderer -p 9100 -m -f -r

As for the settings of the firewall, mpv needs outgoing TCP connections allowed, and python outgoing TCP and UDP connections, as well as incoming TCP connections from local network on local port RENDERER_TCP_PORT (as in command line), incoming UDP connections from local network on local port 1900.

mpv can be configured either from the command line in mpv.bat (but do not remove the --input-ipc-server or there will be no way for the script to control mpv through a named pipe, and it is better not to remove also --idle=yes and --image-display-duration=inf) or in %APPDATA%\mpv\mpv.conf and %APPDATA%\mpv\input.conf (it will affect any playback with mpv beyond the use as a DLNA Renderer). An online manual is available at https://mpv.io/manual/master/.

Example of mpv.conf (change XXXX):  
[default]  
vd-lavc-threads=12  
priority=high  
index=default  
screenshot-template=cap_%F_%p_%02n  
screenshot-format=jpg  
screenshot-directory=C:\Users\XXXX\Downloads  
sub-auto=fuzzy  
vo=gpu  
gpu-api=d3d11  
gpu-context=d3d11  
hwdec=d3d11va  
gpu-hwdec-interop=d3d11va  
hwdec-codecs=all  
vd=libdav1d  
profile=gpu-hq  
interpolation  
video-sync=display-resample  
tscale=mitchell  
tscale-clamp=1  
scale=ewa_lanczossharp  
dscale=ewa_lanczossharp  
cscale=ewa_lanczossharp  
dither-depth=8  
hdr-compute-peak=no  
audio-pitch-correction=yes  
volume=90  
volume-max=100  
ontop=yes  

Example of input.conf:  
ctrl+d osd-msg vf toggle d3d11vpp=deint=yes:interlaced-only=no:mode=adaptive
