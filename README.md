# DLNAmpvRenderer

A script in Python 3 to turn mpv into a DLNA/UPnP renderer

DLNAmpvRenderer is an application written in Python 3 designed as a wrapper for mpv to use the player as a DLNA/UPnP renderer, on a computer running under Windows. The script does not need any other package, only the presence of an executable of mpv is required. The application has been tested with a few DLNA controlers (Windows Media Player Digital Media Controller, Bubble UPnP, UPnPlay, DLNAPlayOn) but should work with any DLNA compliant controler. Subtitles management is enabled through the DIDL description ('subtitlefileuri' or 'captioninfo'/'captioninfoex' tags) or the use of a 'captioninfo.sec' header in the response to the HEAD/GET request for the content to be played.

To install the application:

- of course, install Python 3
- copy DLNAmpvRenderer.py, icon.png and mpv.bat in the same folder
- install mpv (https://mpv.io/installation/)
- open mpv.bat and, if needed, change the path of mpv executable (more customization can be made later on)
- allow mpv and python to communicate through the firewall (for more precise needs, see below)

To run the application:

 DLNAmpvRenderer -h to display the complete syntax of command line and abbreviated commands
    
 DLNAmpvRenderer [-h] [--port RENDERER_TCP_PORT] [--minimize] [--fullscreen] [--wmpdmc_no_mkv] [--trust_controler] [--verbosity VERBOSE]  
    
  -- port RENDERER_TCP_PORT: the port used by the renderer on the local machine sent to the controlers in the advertisements and the answers to the search requests    
  -- minimize: when set, minimizes the window of mpv when inactive and restore it to its previous size when a playback is launched (useful when displaying photos as some controlers stop the playback between two consecutive pictures or when playing music as there is no use showing the window)    
  -- fullscreen: when set, makes mpv go fullscreen each time a playback starts (can be combined with 'minimize')    
  -- wmpdmc_no_mkv: when set, Windows Media Player Digital Media Controller will transcode 'mkv' (matroska) files to 'mpegts' before streaming the content, allowing remote control of the playback, otherwise, the 'mkv' file will be streamed as it is, and the seekbar will probably be inactive in WMPDMC (but available in mpv)    
  -- trust_controler: when set, the URL of the content sent to the renderer is not checked before being passed to mpv (useful to play local content by sending the path to the file, if the controler allows it, which is the case of DLNAPlayOn)    
  -- verbosity VERBOSE: for troubleshooting purposes, from 0 (default) to 2  

 Example: DLNAmpvRenderer -p 9100 -m -f -t

As for the settings of the firewall, mpv needs outgoing TCP connections allowed, and python outgoing TCP and UDP connections, as well as incoming TCP connections from local network on local port RENDERER_TCP_PORT (as in command line), incoming UDP connections from local network on local port 1900.

mpv can be configured either from the command line in mpv.bat (but do not remove the --input-ipc-server or there will be no way for the script to control mpv through a named pipe, and it is better not to remove also --idle=yes and --image-display-duration=inf) or in %APPDATA%\mpv\mpv.conf and %APPDATA%\mpv\input.conf (it will affect any playback with mpv beyond the use as a DLNA Renderer). An online manual is available at https://mpv.io/manual/master/.
