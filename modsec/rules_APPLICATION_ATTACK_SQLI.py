# ------------------------------------------------------------------------
# 如下规则参考 OWASP CRS 编写的代码
# 本代码基于 Apache 2.0 许可证发布
# ------------------------------------------------------------------------

# -=[ sql注入检测 ]=- 检测
def sql_detection():
    runles={
        "headers:Cookie":[
            r"(?i)\W+\d*?\s*?\bhaving\b\s*?[^\s\-]", # 检测可能包含的 HAVING 子句
            r"(?i)(?:\binclude\s*\([^)]*|mosConfig_absolute_path|_CONF\[path\]|_SERVER\[DOCUMENT_ROOT\]|GALLERY_BASEDIR|path\[docroot\]|appserv_root|config\[root_dir\])=(?:file|ftps?|https?)://",
        ],
        "http_byte":[
             r"(?i)(?:(?:url|jar):)?(?:a(?:cap|f[ps]|ttachment)|b(?:eshare|itcoin|lob)|c(?:a(?:llto|p)|id|vs|ompress.(?:zlib|bzip2))|d(?:a(?:v|ta)|ict|n(?:s|tp))|e(?:d2k|xpect)|f(?:(?:ee)?d|i(?:le|nger|sh)|tps?)|g(?:it|o(?:pher)?|lob)|h(?:323|ttps?)|i(?:ax|cap|(?:ma|p)ps?|rc[6s]?)|ja(?:bbe)?r|l(?:dap[is]?|ocal_file)|m(?:a(?:ilto|ven)|ms|umble)|n(?:e(?:tdoc|ws)|fs|ntps?)|ogg|p(?:aparazzi|h(?:ar|p)|op(?:2|3s?)|r(?:es|oxy)|syc)|r(?:mi|sync|tm(?:f?p)?|ar)|s(?:3|ftp|ips?|m(?:[bs]|tps?)|n(?:ews|mp)|sh(?:2(?:.(?:s(?:hell|(?:ft|c)p)|exec|tunnel))?)?|vn(?:\+ssh)?)|t(?:e(?:amspeak|lnet)|ftp|urns?)|u(?:dp|nreal|t2004)|v(?:entrilo|iew-source|nc)|w(?:ebcal|ss?)|x(?:mpp|ri)|zip)://(?:[^@]+@)?([^/]*)"
        ]
    }
    help="[ -sql注入检测- ]"
    return runles,help

def sql_detection_response():
    runles = {"headers:Cookie|http_byte|uri":[
                r"(?i)("
            r"MySqlClient|SQL error|Oracle error|JET Database Engine|Procedure or function|"
            r"SQLite\.Exception|\[IBM\]\[CLI Driver\]\[DB2/6000\]|"
            r"the used select statements have different number of columns|"
            r"org\.postgresql\.util\.PSQLException|Access Database Engine|"
            r"Incorrect syntax near|Syntax error in string in query expression|"
            r"SQLiteException|' doesn't exist|CLI Driver|on MySQL result index|"
            r"sybase|com\.informix\.jdbc|\[MySQL\]\[ODBC|Error|has occurred in the vicinity of:|"
            r"Sintaxis incorrecta cerca de|MySQL server version for the right syntax to use|"
            r"com\.mysql\.jdbc\.exceptions|You have an error in your SQL syntax near|"
            r"You have an error in your SQL syntax;|"
            r"An illegal character has been found in the statement|"
            r"pg_query\(\) \[:|supplied argument is not a valid MySQL|"
            r"mssql_query\(\)|mysql_fetch_array\(\)|Exception|java\.sql\.SQLException|"
            r"Column count doesn't match value count at row|Sybase message|SQL Server|"
            r"PostgreSQL query failed:|Dynamic SQL Error|System\.Data\.SQLite\.SQLiteException|"
            r"SQLite/JDBCDriver|Unclosed quotation mark before the character string|"
            r"System\.Data\.SqlClient\.|Unclosed quotation mark after the character string|"
            r"System\.Data\.OleDb\.OleDbException|\[DM_QUERY_E_SYNTAX\]|\[SqlException|"
            r"Unexpected end of command in statement|valid PostgreSQL result|pg_exec\(\) \[:|"
            r"\[SQL Server\]|\[SQLITE_ERROR\]|Microsoft OLE DB Provider for ODBC Drivers|"
            r"PostgreSQL|org\.hsqldb\.jdbc|ADODB\.Field \(0x800A0BCD\)|SQL syntax|"
            r"Exception|System\.Data\.SqlClient\.SqlException|Data type mismatch in criteria expression\.|"
            r"Driver|DB2 SQL error|Sybase message:|ORA-|"
            r"\[Microsoft\]\[ODBC SQL Server Driver\]|'80040e14'|"
            r"Microsoft OLE DB Provider for SQL Server| in query expression|"
            r"Npgsql\.|valid MySQL result|supplied argument is not a valid PostgreSQL result|"
            r"db2_|Ingres SQLSTATE|Column count doesn't match|Warning|"
            r"\[Microsoft\]\[ODBC Microsoft Access Driver\]|\[Macromedia\]\[SQLServer JDBC Driver\]|"
            r"<b>Warning</b>: ibase_|Roadhouse\.Cms\.|DB2 SQL error:|SQLSTATE\[|"
            r"MySQLSyntaxErrorException|check the manual that corresponds to your MySQL server version|"
            r"check the manual that fits your MySQL server version|"
            r"check the manual that corresponds to your MariaDB server version|"
            r"check the manual that fits your MariaDB server version|"
            r"check the manual that corresponds to your Drizzle server version|"
            r"check the manual that fits your Drizzle server version|"
            r"Zend_Db_Adapter_Mysqli_Exception|Zend_Db_Statement_Mysqli_Exception|"
            r"MySqlException|Syntax error or access violation|"
            r"MemSQL does not support this type of query|is not supported by MemSQL|"
            r"unsupported nested scalar subselect|PG::SyntaxError:|"
            r"syntax error at or near|ERROR: parser: parse error at or near|"
            r"org\.postgresql\.jdbc|PSQLException|"
            r"System\.Data\.SqlClient\.SqlConnection\.OnError|Microsoft SQL Native Client error|"
            r"com\.jnetdirect\.jsql|macromedia\.jdbc\.sqlserver|"
            r"Zend_Db_Adapter_Sqlsrv_Exception|Zend_Db_Statement_Sqlsrv_Exception|"
            r"com\.microsoft\.sqlserver\.jdbc|SQLSrvException|SQLServerException|"
            r"quoted string not properly terminated|SQL command not properly ended|"
            r"macromedia\.jdbc\.oracle|oracle\.jdbc|Zend_Db_Adapter_Oracle_Exception|"
            r"Zend_Db_Statement_Oracle_Exception|OracleException|com\.ibm\.db2\.jcc|"
            r"Zend_Db_Adapter_Db2_Exception|Zend_Db_Statement_Db2_Exception|"
            r"ibm_db_dbi\.ProgrammingError|Informix ODBC Driver|ODBC Informix driver|"
            r"weblogic\.jdbc\.informix|IfxException|org\.firebirdsql\.jdbc|"
            r"Microsoft\.Data\.SQLite\.SQLiteException|SQLite error|sqlite3\.OperationalError:|"
            r"SQLite3::SQLException|org\.sqlite\.JDBC|DriverSapDB|com\.sap\.dbtech\.jdbc|"
            r"Invalid keyword or missing delimiter|SybSQLException|"
            r"Sybase\.Data\.AseClient|com\.sybase\.jdbc|com\.ingres\.gcf\.jdbc|"
            r"com\.frontbase\.jdbc|Syntax error 1\. Missing|Semantic error|org\.h2\.jdbc|"
            r"\[42000-192\]|\[MonetDB\]\[ODBC Driver|nl\.cwi\.monetdb\.jdbc|"
            r"Syntax error: Encountered|org\.apache\.derby|ERROR 42X01|"
            r"com\.vertica\.jdbc|org\.jkiss\.dbeaver\.ext\.vertica|"
            r"com\.vertica\.dsi\.dataengine|com\.mckoi\.JDBCDriver|"
            r"com\.mckoi\.database\.jdbc|com\.facebook\.presto\.jdbc|"
            r"io\.prestosql\.jdbc|com\.simba\.presto\.jdbc|"
            r"UNION query has different number of fields:|Altibase\.jdbc\.driver|"
            r"com\.mimer\.jdbc|Syntax error: failed at position|io\.crate\.client\.jdbc|"
            r"encountered after end of query|A comparison operator is required here|"
            r"-10048: Syntax error|SQ074: Line|SR185: Undefined procedure|"
            r"SQ200: No table|Virtuoso S0002 Error|\[Virtuoso Driver\]\[Virtuoso Server\]|"
            r"\[Virtuoso iODBC Driver\]\[Virtuoso Server\]|"
            r"Conversion failed when converting the varchar value|"
            r"invalid input syntax for integer:|XPATH syntax error"
            r")"
        ]
    }
    help="[ -sql注入检测- ]"
    return runles,help


