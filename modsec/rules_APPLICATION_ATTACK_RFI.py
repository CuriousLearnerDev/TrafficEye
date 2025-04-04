# ------------------------------------------------------------------------
# 如下规则参考 OWASP CRS 编写的代码
# 本代码基于 Apache 2.0 许可证发布
# ------------------------------------------------------------------------

# -=[ 远程文件包含检测 ]=- 检测
def Rce_detection():
    runles={
        "uri|http_byte":[
            r"^(?i:file|ftps?)://(?:\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})",
            r"(?i)(?:\binclude\s*\([^)]*|mosConfig_absolute_path|_CONF\[path\]|_SERVER\[DOCUMENT_ROOT\]|GALLERY_BASEDIR|path\[docroot\]|appserv_root|config\[root_dir\])=(?:file|ftps?|https?)://",
        ],
        "http_byte":[
             r"(?i)(?:(?:url|jar):)?(?:a(?:cap|f[ps]|ttachment)|b(?:eshare|itcoin|lob)|c(?:a(?:llto|p)|id|vs|ompress.(?:zlib|bzip2))|d(?:a(?:v|ta)|ict|n(?:s|tp))|e(?:d2k|xpect)|f(?:(?:ee)?d|i(?:le|nger|sh)|tps?)|g(?:it|o(?:pher)?|lob)|h(?:323|ttps?)|i(?:ax|cap|(?:ma|p)ps?|rc[6s]?)|ja(?:bbe)?r|l(?:dap[is]?|ocal_file)|m(?:a(?:ilto|ven)|ms|umble)|n(?:e(?:tdoc|ws)|fs|ntps?)|ogg|p(?:aparazzi|h(?:ar|p)|op(?:2|3s?)|r(?:es|oxy)|syc)|r(?:mi|sync|tm(?:f?p)?|ar)|s(?:3|ftp|ips?|m(?:[bs]|tps?)|n(?:ews|mp)|sh(?:2(?:.(?:s(?:hell|(?:ft|c)p)|exec|tunnel))?)?|vn(?:\+ssh)?)|t(?:e(?:amspeak|lnet)|ftp|urns?)|u(?:dp|nreal|t2004)|v(?:entrilo|iew-source|nc)|w(?:ebcal|ss?)|x(?:mpp|ri)|zip)://(?:[^@]+@)?([^/]*)"
        ]
    }
    help="[ -远程文件包含检测- ]"
    return runles,help
