# nullx
Nullx is a transcoding server which converts input audio/video files (with multiple tracks) into h264/aac/mov_text format
and optionally uploads resulted files into elliptics storage.

Nullx spawns a pool of processes using `ribosome::fpool` each one transcodes media file using ffmpeg.
If process crashes it will be automatically restarted.

Transcoding is asynchronous, server will reply to client after it is completed.
If elliptics upload options are not specified in the request, server will send transcoded file to client in reply.

# Server config options
`tmp_dir` - temporal directory where input and resulted files are stored during transcoding.
`transcoding_workers` - number of transcoding processes, default value is 16.

# Elliptics upload options
If request contains following headers, transcoded file will not be returned to client but instead will be written into elliptics.

`X-Ell-Groups` - groups in the format `1:2:3` where transcoded file should be written.
`X-Ell-ID` - hex ID (128 bytes, if less, the rest will be filled with zeroes) of the key to upload.
Alternatively you can specify `X-Ell-Bucket` and `X-Ell-Key` - bucket (namespace)/key pair of the key which will be used to upload
transcoded file into elliptics.

Also you can specify additional metadata headers, which will force server to upload some metadata of the transcoded file into elliptics.
`X-Ell-Metadata-Groups` - groups in the format `1:2:3` where metadata for transcoded file should be written.
`X-Ell-Metadata-ID` or `X-Ell-Metadata-Bucket` + `X-Ell-Metadata-Key` - which key should be used to write transcoded file metadata.
