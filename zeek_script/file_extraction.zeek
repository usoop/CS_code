# 文件类型参考：https://developer.mozilla.org/zh-CN/docs/Web/HTTP/Basics_of_HTTP/MIME_types/Common_types.
global mime_to_ext: table[string] of string = {
    ["application/x-dosexec"] = "exe",
    ["text/plain"] = "txt",
    ["image/jpeg"] = "jpg",
    ["image/png"] = "png",
    ["text/html"] = "html",
    ["image/svg+xml"] = "svg+xml",
    ["text/javascript"] = "script",
    ["text/css"] = "css",
    ["font/woff2"] = "font",
    ["image/gif"] = "gif",
    ["audio/mpeg"] = "media",
    ["audio/aac"]="aac",
    ["application/x-abiword"]="abw",
    ["application/x-freearc"]="arc",
    ["video/x-msvideo"]="avi",
    ["application/vnd.amazon.ebook"]="azw",
    ["application/octet-stream"]="bin",
    ["image/bmp"]="bmp",
    ["application/x-bzip"]="bz",
    ["application/x-bzip2"]="bz2",
    ["application/x-csh"]="csh",
    ["text/csv"]="csv",
    ["application/msword"]="doc",
    ["application/vnd.openxmlformats-officedocument.wordprocessingml.document"]="docx",
    ["application/vnd.ms-fontobject"]="eot",
    ["application/epub+zip"]="epub",
    ["image/vnd.microsoft.icon"]="ico",
    ["text/calendar"]="ics",
    ["application/java-archive"]="jar",
    ["application/json"]="json",
    ["application/ld+json"]="jsonld",
    ["audio/midi audio/x-midi"]="midi",
    ["video/mpeg"]="mpeg",
    ["application/vnd.apple.installer+xml"]="mpkg",
    ["application/vnd.oasis.opendocument.presentation"]="odp",
    ["application/vnd.oasis.opendocument.spreadsheet"]="ods",
    ["application/vnd.oasis.opendocument.text"]="odt",
    ["audio/ogg"]="oga",
    ["video/ogg"]="ogv",
    ["application/ogg"]="ogx",
    ["font/otf"]="otf",
    ["application/pdf"]="pdf",
    ["application/vnd.ms-powerpoint"]="ppt",
    ["application/vnd.openxmlformats-officedocument.presentationml.presentation"]="pptx",
    ["application/x-rar-compressed"]="rar",
    ["application/rtf"]="rtf",
    ["application/x-sh"]="sh",
    ["application/x-shockwave-flash"]="swf",
    ["application/x-tar"]="tar",
    ["image/tiff"]="tiff",
    ["font/ttf"]="ttf",
    ["application/vnd.visio"]="vsd",
    ["audio/wav"]="wav",
    ["audio/webm"]="weba",
    ["video/webm"]="webm",
    ["image/webp"]="webp",
    ["font/woff"]="woff",
    ["application/xhtml+xml"]="xhtml",
    ["application/vnd.ms-excel"]="xls",
    ["application/vnd.openxmlformats-officedocument.spreadsheetml.sheet"]="xlsx",
    ["application/vnd.mozilla.xul+xml"]="xul",
    ["application/zip"]="zip",
    ["video/3gpp"]="3gp",
    ["video/3gpp2"]="3g2",
    ["application/x-7z-compressed"]="7z",
};

event file_sniff(f: fa_file, meta: fa_metadata)
    {
    if ( f$source != "HTTP" )
        return;
    if ( ! meta?$mime_type )
        return;
    if ( meta$mime_type !in mime_to_ext )
        return;
    local fname = fmt("%s-%s.%s", f$source, f$id, mime_to_ext[meta$mime_type]);

    Files::add_analyzer(f, Files::ANALYZER_EXTRACT, [$extract_filename=fname]);
    }