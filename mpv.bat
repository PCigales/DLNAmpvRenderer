@setlocal enabledelayedexpansion
@"C:\Program Files\Mpv\mpv.exe" --input-ipc-server=\\.\pipe\mpv_!renderer_name! --pause --idle=yes --image-display-duration=inf --autofit=50%%
@endlocal