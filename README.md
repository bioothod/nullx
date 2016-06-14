# nullx
Nullx is a transcoding server which converts input audio/video files (with multiple tracks) into h264/aac/mov_text format
and optionally uploads resulted files into elliptics storage.

Nullx spawns a pool of processes using `ribosome::fpool` each one transcodes media file using ffmpeg.
If process crashes it will be automatically restarted.

Transcoding is asynchronous, server will reply to client after it is completed.
If elliptics upload options are not specified in the request, server will send transcoded file to client in reply.
