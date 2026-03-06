#!/bin/bash
#================================================================
# Oracle_Linux 보안 진단 스크립트
# KISA 주요정보통신기반시설 기술적 취약점 분석·평가 기준
#================================================================
# 버전  : 2603070
# 대상  : Oracle_Linux
# 항목  : D-01 ~ D-26 (26개)
# 제작  : Seedgen
#================================================================
META_STD="KISA"

#================================================================
# INIT
#================================================================
META_VER="1.0"
META_PLAT="Oracle"
META_TYPE="DBMS"

# XML 특수문자 이스케이프
xml_escape() {
    local s="$1"
    s="${s//&/&amp;}"
    s="${s//</&lt;}"
    s="${s//>/&gt;}"
    s="${s//\"/&quot;}"
    echo "$s"
}

# 결과 출력 함수
output_checkpoint() {
    local CODE="$1"
    local CAT="$2"
    local NAME="$3"
    local IMP="$4"
    local STD="$5"
    local RES="$6"
    local DESC="$7"
    local DT="$8"

    case "$RES" in
        "Y")   echo -e "    [[32mY[0m] $CODE $NAME" ;;
        "N")   echo -e "    [[31mN[0m] $CODE $NAME" ;;
        "M")   echo -e "    [[33mM[0m] $CODE $NAME" ;;
        "N/A") echo -e "    [[90m-[0m] $CODE $NAME" ;;
        *)     echo -e "    [-] $CODE $NAME" ;;
    esac

    local E_NAME; E_NAME=$(xml_escape "$NAME")
    local E_DESC; E_DESC=$(xml_escape "$DESC")
    local E_STD; E_STD=$(xml_escape "$STD")
    cat >> "$OUTPUT_FILE" << CPEOF
        <cp>
            <code>$CODE</code>
            <cat>$CAT</cat>
            <n>$E_NAME</n>
            <imp>$IMP</imp>
            <std>$E_STD</std>
            <res>$RES</res>
            <desc>$E_DESC</desc>
            <dt><![CDATA[$DT]]></dt>
        </cp>
CPEOF
}

#================================================================
# CONNECT — 플랫폼별 커스터마이즈 영역
# (클라이언트 확인, 연결정보 입력, 연결 테스트, 버전 변수 세팅)
#================================================================

# SQL 실행 함수
run_sql() {
    local SQL="$1"
    echo "$SQL" | $SQLPLUS_CMD 2>/dev/null | grep -v "^$" | grep -v "^SQL>" | grep -v "^Connected" | grep -v "rows selected"
}

echo ""
echo "============================================================"
echo " Oracle DB 보안 진단 스크립트"
echo "============================================================"
echo ""
echo "[연결 정보 입력]"
echo ""

# ORACLE_HOME 확인
if [ -z "$ORACLE_HOME" ]; then
    echo -n "ORACLE_HOME Path: "
    read ORACLE_HOME
    if [ ! -d "$ORACLE_HOME" ]; then
        echo "[!] ORACLE_HOME 디렉터리를 찾을 수 없습니다."
        exit 1
    fi
    export ORACLE_HOME
fi

# sqlplus 클라이언트 확인
SQLPLUS_BIN="$ORACLE_HOME/bin/sqlplus"
if [ ! -x "$SQLPLUS_BIN" ]; then
    SQLPLUS_BIN=$(which sqlplus 2>/dev/null)
    if [ -z "$SQLPLUS_BIN" ]; then
        echo "[!] sqlplus를 찾을 수 없습니다."
        exit 1
    fi
fi

# 연결 정보 입력
echo -n "User (default: sys): "
read DB_USER
DB_USER=${DB_USER:-sys}

echo -n "Password: "
read -s DB_PASS
echo ""

if [ -z "$DB_PASS" ]; then
    echo "[!] 비밀번호를 입력해주세요."
    exit 1
fi

echo -n "SID (default: orcl): "
read DB_SID
DB_SID=${DB_SID:-orcl}

echo -n "Connect as SYSDBA? (y/n, default: y): "
read AS_SYSDBA
AS_SYSDBA=${AS_SYSDBA:-y}

# Oracle 연결 명령어 구성
if [ "$AS_SYSDBA" == "y" ] || [ "$AS_SYSDBA" == "Y" ]; then
    SQLPLUS_CMD="$SQLPLUS_BIN -S $DB_USER/$DB_PASS@$DB_SID as sysdba"
else
    SQLPLUS_CMD="$SQLPLUS_BIN -S $DB_USER/$DB_PASS@$DB_SID"
fi

# 연결 테스트
echo ""
echo "[연결 테스트 중...]"
DB_VERSION=$(echo "SELECT banner FROM v\$version WHERE ROWNUM = 1;" | $SQLPLUS_CMD 2>/dev/null | grep -i "Oracle" | head -1)
if [ -z "$DB_VERSION" ]; then
    echo "[!] Oracle 연결 실패"
    exit 1
fi
echo "[OK] $DB_VERSION 연결 성공"
echo ""

# Oracle 버전 정보
ORACLE_VERSION=$(echo "SELECT version FROM v\$instance;" | $SQLPLUS_CMD 2>/dev/null | grep -E "^[0-9]" | head -1)

#================================================================
# COLLECT
#================================================================
META_DATE=$(date +%Y-%m-%dT%H:%M:%S%:z)
SYS_HOST=$(hostname)
SYS_DOM=$(hostname -d 2>/dev/null || echo "N/A")
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
OUTPUT_FILE="${SCRIPT_DIR}/${META_PLAT}_${SYS_HOST}_$(date +%Y%m%d_%H%M%S).xml"

#================================================================
# CHECK FUNCTIONS
#================================================================

check01() {
    local CODE="D-01"
    local CAT="계정관리"
    local NAME="기본 계정의 비밀번호, 정책 등을 변경하여 사용"
    local IMP="상"
    local STD="기본 계정의 초기 비밀번호를 변경하거나 잠금설정한 경우"
    local RES=""
    local DESC=""
    local DT=""

        # 12c+ 추가 기본 계정 포함
        local DEFAULT_ACCOUNTS=$(echo "
    SET LINESIZE 200
    SET PAGESIZE 100
    SELECT username, account_status, profile FROM dba_users
    WHERE username IN ('SCOTT', 'SYSTEM', 'SYS', 'DBSNMP', 'OUTLN', 'HR', 'OE', 'PM', 'SH',
        'ANONYMOUS', 'APEX_PUBLIC_USER', 'FLOWS_FILES', 'APEX_040000', 'APEX_040200',
        'XDB', 'CTXSYS', 'MDSYS', 'ORDSYS', 'EXFSYS', 'WMSYS', 'OLAPSYS', 'ORDDATA',
        'ORDPLUGINS', 'SI_INFORMTN_SCHEMA', 'SYSMAN', 'MGMT_VIEW', 'OWBSYS', 'OWBSYS_AUDIT',
        'APPQOSSYS', 'GSMADMIN_INTERNAL', 'GSMCATUSER', 'GSMUSER', 'SYSBACKUP', 'SYSDG',
        'SYSKM', 'SYSRAC', 'SYS\$UMF', 'AUDSYS', 'DBSFWUSER', 'GGSYS', 'DIP', 'REMOTE_SCHEDULER_AGENT');
    " | $SQLPLUS_CMD 2>/dev/null)

        # SYS, SYSTEM 제외하고 활성화된 기본 계정 체크 (12c+ 추가 계정 포함)
        local OPEN_DEFAULT=$(echo "
    SELECT username FROM dba_users
    WHERE username IN ('SCOTT', 'DBSNMP', 'OUTLN', 'HR', 'OE', 'PM', 'SH',
        'ANONYMOUS', 'APEX_PUBLIC_USER', 'FLOWS_FILES', 'APEX_040000', 'APEX_040200',
        'XDB', 'CTXSYS', 'MDSYS', 'ORDSYS', 'EXFSYS', 'WMSYS', 'OLAPSYS', 'ORDDATA',
        'ORDPLUGINS', 'SI_INFORMTN_SCHEMA', 'SYSMAN', 'MGMT_VIEW', 'OWBSYS', 'OWBSYS_AUDIT',
        'APPQOSSYS', 'GSMADMIN_INTERNAL', 'GSMCATUSER', 'GSMUSER', 'SYSBACKUP', 'SYSDG',
        'SYSKM', 'SYSRAC', 'AUDSYS', 'DBSFWUSER', 'GGSYS', 'DIP', 'REMOTE_SCHEDULER_AGENT')
    AND account_status = 'OPEN';
    " | $SQLPLUS_CMD 2>/dev/null | grep -v "^USERNAME" | grep -v "^-" | grep -v "^$" | grep -v "no rows")

        DT="[기본 계정 상태]\n$DEFAULT_ACCOUNTS"

        if [ -z "$OPEN_DEFAULT" ]; then
            RES="Y"
            DESC="기본 계정이 잠금 설정되어 있음"
        else
            RES="N"
            DESC="활성화된 기본 계정 존재"
            DT="[활성화된 기본 계정]\n$OPEN_DEFAULT\n\n$DT"
        fi

    output_checkpoint "$CODE" "$CAT" "$NAME" "$IMP" "$STD" "$RES" "$DESC" "$DT"
}

check02() {
    local CODE="D-02"
    local CAT="계정관리"
    local NAME="데이터베이스의 불필요 계정을 제거하거나, 잠금설정 후 사용"
    local IMP="상"
    local STD="계정 정보를 확인하여 불필요한 계정이 없는 경우"
    local RES=""
    local DESC=""
    local DT=""

        local RES="M"
        local DESC="계정 목록 수동 확인 필요"

        local ALL_ACCOUNTS=$(echo "
    SET LINESIZE 200
    SET PAGESIZE 100
    SELECT username, account_status, lock_date, expiry_date, profile
    FROM dba_users ORDER BY username;
    " | $SQLPLUS_CMD 2>/dev/null)

        DT="[계정 목록 - 불필요 계정 여부 확인 필요]\n$ALL_ACCOUNTS"

    output_checkpoint "$CODE" "$CAT" "$NAME" "$IMP" "$STD" "$RES" "$DESC" "$DT"
}

check03() {
    local CODE="D-03"
    local CAT="계정관리"
    local NAME="비밀번호 사용 기간 및 복잡도를 기관의 정책에 맞도록 설정"
    local IMP="상"
    local STD="기관 정책에 맞게 비밀번호 사용 기간 및 복잡도 설정이 적용된 경우"
    local RES=""
    local DESC=""
    local DT=""

        local PROFILE_POLICY=$(echo "
    SET LINESIZE 200
    SET PAGESIZE 100
    SELECT profile, resource_name, limit FROM dba_profiles
    WHERE resource_type = 'PASSWORD' ORDER BY profile, resource_name;
    " | $SQLPLUS_CMD 2>/dev/null)

        DT="[프로파일 비밀번호 정책]\n$PROFILE_POLICY"

        local VERIFY_FUNC=$(echo "
    SELECT profile, limit FROM dba_profiles
    WHERE resource_name = 'PASSWORD_VERIFY_FUNCTION' AND limit != 'NULL';
    " | $SQLPLUS_CMD 2>/dev/null | grep -v "^PROFILE" | grep -v "^-" | grep -v "^$" | grep -v "no rows")

        if [ -n "$VERIFY_FUNC" ]; then
            RES="Y"
            DESC="비밀번호 검증 함수가 설정됨"
        else
            RES="N"
            DESC="비밀번호 검증 함수(PASSWORD_VERIFY_FUNCTION)가 설정되지 않음"
        fi

    output_checkpoint "$CODE" "$CAT" "$NAME" "$IMP" "$STD" "$RES" "$DESC" "$DT"
}

check04() {
    local CODE="D-04"
    local CAT="계정관리"
    local NAME="데이터베이스 관리자 권한을 꼭 필요한 계정 및 그룹에 대해서만 허용"
    local IMP="상"
    local STD="관리자 권한이 필요한 계정 및 그룹에만 관리자 권한이 부여된 경우"
    local RES=""
    local DESC=""
    local DT=""

        local RES="M"
        local DESC="SYSDBA/DBA 권한 보유 계정 수동 확인 필요"

        local SYSDBA_USERS=$(echo "
    SET LINESIZE 200
    SELECT username FROM v\$pwfile_users WHERE SYSDBA = 'TRUE';
    " | $SQLPLUS_CMD 2>/dev/null)

        local DBA_USERS=$(echo "
    SELECT grantee FROM dba_role_privs WHERE granted_role = 'DBA';
    " | $SQLPLUS_CMD 2>/dev/null)

        local ADMIN_OPTION=$(echo "
    SELECT grantee, privilege FROM dba_sys_privs
    WHERE admin_option = 'YES'
    AND grantee NOT IN ('SYS', 'SYSTEM', 'DBA')
    AND grantee NOT IN (SELECT grantee FROM dba_role_privs WHERE granted_role = 'DBA');
    " | $SQLPLUS_CMD 2>/dev/null)

        DT="[SYSDBA 권한 보유 계정]\n$SYSDBA_USERS\n\n[DBA 롤 보유 계정]\n$DBA_USERS\n\n[Admin Option 보유 계정]\n$ADMIN_OPTION"

    output_checkpoint "$CODE" "$CAT" "$NAME" "$IMP" "$STD" "$RES" "$DESC" "$DT"
}

check05() {
    local CODE="D-05"
    local CAT="계정관리"
    local NAME="비밀번호 재사용에 대한 제약 설정"
    local IMP="중"
    local STD="비밀번호 재사용 제한 설정을 적용한 경우"
    local RES=""
    local DESC=""
    local DT=""

        local REUSE_POLICY=$(echo "
    SET LINESIZE 200
    SELECT profile, resource_name, limit FROM dba_profiles
    WHERE resource_name IN ('PASSWORD_REUSE_TIME', 'PASSWORD_REUSE_MAX');
    " | $SQLPLUS_CMD 2>/dev/null)

        DT="[비밀번호 재사용 정책]\n$REUSE_POLICY"

        local REUSE_SET_RAW=$(echo "
    SET HEADING OFF
    SET FEEDBACK OFF
    SET PAGESIZE 0
    SELECT COUNT(*) FROM dba_profiles
    WHERE resource_name IN ('PASSWORD_REUSE_TIME', 'PASSWORD_REUSE_MAX')
    AND limit != 'UNLIMITED' AND limit != 'DEFAULT';
    " | $SQLPLUS_CMD 2>/dev/null)
        # 숫자만 추출 (공백, 줄바꿈 제거)
        local REUSE_SET=$(echo "$REUSE_SET_RAW" | tr -d '[:space:]' | grep -oE '^[0-9]+' | head -1)
        REUSE_SET=${REUSE_SET:-0}

        if [ "$REUSE_SET" -gt 0 ] 2>/dev/null; then
            RES="Y"
            DESC="비밀번호 재사용 제한이 설정됨"
        else
            RES="N"
            DESC="비밀번호 재사용 제한이 설정되지 않음"
        fi

    output_checkpoint "$CODE" "$CAT" "$NAME" "$IMP" "$STD" "$RES" "$DESC" "$DT"
}

check06() {
    local CODE="D-06"
    local CAT="계정관리"
    local NAME="DB 사용자 계정을 개별적으로 부여하여 사용"
    local IMP="중"
    local STD="사용자별 계정을 사용하고 있는 경우"
    local RES=""
    local DESC=""
    local DT=""

        local RES="M"
        local DESC="사용자별 개별 계정 사용 여부 수동 확인 필요"

        local USER_LIST=$(echo "
    SET LINESIZE 200
    SELECT username, created, account_status FROM dba_users
    WHERE username NOT IN ('SYS', 'SYSTEM', 'ANONYMOUS', 'APEX_PUBLIC_USER', 'FLOWS_FILES',
    'APEX_040000', 'APEX_030200', 'OUTLN', 'XDB', 'CTXSYS', 'DBSNMP', 'MDSYS', 'ORDSYS',
    'EXFSYS', 'WMSYS', 'OLAPSYS', 'ORDDATA', 'ORDPLUGINS', 'SI_INFORMTN_SCHEMA', 'SYSMAN',
    'MGMT_VIEW', 'SCOTT', 'OWBSYS', 'OWBSYS_AUDIT', 'SPATIAL_CSW_ADMIN_USR', 'SPATIAL_WFS_ADMIN_USR')
    ORDER BY username;
    " | $SQLPLUS_CMD 2>/dev/null)

        DT="[사용자 계정 목록 - 개별 계정 사용 여부 확인 필요]\n$USER_LIST"

    output_checkpoint "$CODE" "$CAT" "$NAME" "$IMP" "$STD" "$RES" "$DESC" "$DT"
}

check07() {
    local CODE="D-07"
    local CAT="계정관리"
    local NAME="root 권한으로 서비스 구동 제한"
    local IMP="중"
    local STD="DBMS가 root 계정 또는 root 권한이 아닌 별도의 계정 및 권한으로 구동되고 있는 경우"
    local RES=""
    local DESC=""
    local DT=""

    local ORA_PROC=$(ps -ef | grep pmon | grep -v grep | head -1)
    local PROC_USER=$(echo "$ORA_PROC" | awk '{print $1}')

    local LSNR_PROC=$(ps -ef | grep tnslsnr | grep -v grep | head -1)
    local LSNR_USER=$(echo "$LSNR_PROC" | awk '{print $1}')

    DT="[Oracle PMON 프로세스]\n$ORA_PROC\n\n[Listener 프로세스]\n$LSNR_PROC"

    if [ -z "$ORA_PROC" ]; then
        RES="N/A"
        DESC="Oracle 프로세스를 찾을 수 없음"
    elif [ "$PROC_USER" == "root" ] || [ "$LSNR_USER" == "root" ]; then
        RES="N"
        DESC="Oracle 또는 Listener가 root 권한으로 구동 중"
    else
        RES="Y"
        DESC="Oracle이 일반 계정($PROC_USER)으로 구동 중"
    fi

    output_checkpoint "$CODE" "$CAT" "$NAME" "$IMP" "$STD" "$RES" "$DESC" "$DT"
}

check08() {
    local CODE="D-08"
    local CAT="계정관리"
    local NAME="안전한 암호화 알고리즘 사용"
    local IMP="상"
    local STD="해시 알고리즘 SHA-256 이상의 암호화 알고리즘을 사용하고 있는 경우"
    local RES=""
    local DESC=""
    local DT=""

        local PW_VERSIONS=$(echo "
    SET LINESIZE 200
    SELECT username, password_versions FROM dba_users WHERE username NOT LIKE '%\$%';
    " | $SQLPLUS_CMD 2>/dev/null)

        local SQLNET_FILE="$ORACLE_HOME/network/admin/sqlnet.ora"
        local SQLNET_CONTENT=""
        if [ -f "$SQLNET_FILE" ]; then
            SQLNET_CONTENT=$(grep -i "SQLNET.ALLOWED_LOGON_VERSION" "$SQLNET_FILE" 2>/dev/null)
        fi

        DT="[계정별 비밀번호 버전]\n$PW_VERSIONS\n\n[sqlnet.ora 설정]\n$SQLNET_CONTENT"

        # 취약한 암호화 알고리즘 사용 계정 체크 (10G만 있거나, 12C가 없는 경우)
        # - 10G만 있는 경우: 매우 취약
        # - 10G 11G만 있는 경우: 취약 (12C 없음)
        # - 11G만 있는 경우: 12C 해시 없으므로 취약
        # - 12C가 포함된 경우: 양호 (11G 12C, 10G 11G 12C 등)
        local WEAK_PW=$(echo "
    SELECT username FROM dba_users
    WHERE username NOT LIKE '%\$%'
    AND account_status = 'OPEN'
    AND (
        password_versions = '10G'
        OR password_versions = '10G 11G'
        OR password_versions = '11G'
        OR password_versions NOT LIKE '%12C%'
    );
    " | $SQLPLUS_CMD 2>/dev/null | grep -v "^USERNAME" | grep -v "^-" | grep -v "^$" | grep -v "no rows")

        # 10G 해시만 사용하는 매우 취약한 계정 별도 체크
        local VERY_WEAK=$(echo "
    SELECT username FROM dba_users
    WHERE username NOT LIKE '%\$%'
    AND account_status = 'OPEN'
    AND password_versions = '10G';
    " | $SQLPLUS_CMD 2>/dev/null | grep -v "^USERNAME" | grep -v "^-" | grep -v "^$" | grep -v "no rows")

        if [ -z "$WEAK_PW" ]; then
            RES="Y"
            DESC="안전한 암호화 알고리즘(12C) 사용 중"
        elif [ -n "$VERY_WEAK" ]; then
            RES="N"
            DESC="매우 취약한 암호화 알고리즘(10G only) 사용 계정 존재"
            DT="[매우 취약 계정 (10G only)]\n$VERY_WEAK\n\n[12C 미사용 계정]\n$WEAK_PW\n\n$DT"
        else
            RES="N"
            DESC="취약한 암호화 알고리즘 사용 (12C 해시 없음)"
            DT="[12C 미사용 계정]\n$WEAK_PW\n\n$DT"
        fi

    output_checkpoint "$CODE" "$CAT" "$NAME" "$IMP" "$STD" "$RES" "$DESC" "$DT"
}

check09() {
    local CODE="D-09"
    local CAT="계정관리"
    local NAME="일정 횟수의 로그인 실패 시 이에 대한 잠금정책 설정"
    local IMP="중"
    local STD="로그인 시도 횟수를 제한하는 값을 설정한 경우"
    local RES=""
    local DESC=""
    local DT=""

        local LOGIN_POLICY=$(echo "
    SET LINESIZE 200
    SELECT profile, resource_name, limit FROM dba_profiles
    WHERE resource_name = 'FAILED_LOGIN_ATTEMPTS';
    " | $SQLPLUS_CMD 2>/dev/null)

        DT="[로그인 실패 잠금 정책]\n$LOGIN_POLICY"

        local LOGIN_SET_RAW=$(echo "
    SET HEADING OFF
    SET FEEDBACK OFF
    SET PAGESIZE 0
    SELECT COUNT(*) FROM dba_profiles
    WHERE resource_name = 'FAILED_LOGIN_ATTEMPTS'
    AND limit != 'UNLIMITED';
    " | $SQLPLUS_CMD 2>/dev/null)
        # 숫자만 추출 (공백, 줄바꿈 제거)
        local LOGIN_SET=$(echo "$LOGIN_SET_RAW" | tr -d '[:space:]' | grep -oE '^[0-9]+' | head -1)
        LOGIN_SET=${LOGIN_SET:-0}

        if [ "$LOGIN_SET" -gt 0 ] 2>/dev/null; then
            RES="Y"
            DESC="로그인 실패 잠금 정책이 설정됨"
        else
            RES="N"
            DESC="로그인 실패 잠금 정책이 설정되지 않음"
        fi

    output_checkpoint "$CODE" "$CAT" "$NAME" "$IMP" "$STD" "$RES" "$DESC" "$DT"
}

check10() {
    local CODE="D-10"
    local CAT="접근관리"
    local NAME="원격에서 DB 서버로의 접속 제한"
    local IMP="상"
    local STD="DB 서버에 지정된 IP주소에서만 접근 가능하도록 제한한 경우"
    local RES=""
    local DESC=""
    local DT=""

    local RES="M"
    local DESC="listener.ora 및 sqlnet.ora 설정 수동 확인 필요"

    local LISTENER_FILE="$ORACLE_HOME/network/admin/listener.ora"
    local LISTENER_CONTENT=""
    if [ -f "$LISTENER_FILE" ]; then
        LISTENER_CONTENT=$(cat "$LISTENER_FILE" 2>/dev/null)
    else
        LISTENER_CONTENT="파일 없음"
    fi

    local SQLNET_FILE="$ORACLE_HOME/network/admin/sqlnet.ora"
    local VALIDNODE=""
    if [ -f "$SQLNET_FILE" ]; then
        VALIDNODE=$(grep -i "TCP.VALIDNODE" "$SQLNET_FILE" 2>/dev/null)
    fi

    DT="[listener.ora]\n$LISTENER_CONTENT\n\n[sqlnet.ora - TCP.VALIDNODE 설정]\n$VALIDNODE"

    output_checkpoint "$CODE" "$CAT" "$NAME" "$IMP" "$STD" "$RES" "$DESC" "$DT"
}

check11() {
    local CODE="D-11"
    local CAT="접근관리"
    local NAME="DBA 이외의 인가되지 않은 사용자가 시스템 테이블에 접근할 수 없도록 설정"
    local IMP="상"
    local STD="시스템 테이블에 DBA만 접근 가능하도록 설정되어 있는 경우"
    local RES=""
    local DESC=""
    local DT=""

        local SYS_TABLE_ACCESS=$(echo "
    SET LINESIZE 200
    SET PAGESIZE 100
    SELECT grantee, privilege, owner, table_name FROM dba_tab_privs
    WHERE (owner = 'SYS' OR table_name LIKE 'DBA_%')
    AND privilege <> 'EXECUTE'
    AND grantee NOT IN ('PUBLIC', 'DBA', 'SYS', 'SYSTEM', 'SELECT_CATALOG_ROLE',
    'EXECUTE_CATALOG_ROLE', 'DELETE_CATALOG_ROLE', 'EXP_FULL_DATABASE', 'IMP_FULL_DATABASE')
    AND grantee NOT IN (SELECT grantee FROM dba_role_privs WHERE granted_role = 'DBA');
    " | $SQLPLUS_CMD 2>/dev/null)

        DT="[시스템 테이블 접근 권한 (비인가 계정)]\n$SYS_TABLE_ACCESS"

        local ACCESS_COUNT=$(echo "$SYS_TABLE_ACCESS" | grep -v "^GRANTEE" | grep -v "^-" | grep -v "^$" | grep -v "no rows" | wc -l)

        if [ "$ACCESS_COUNT" -eq 0 ]; then
            RES="Y"
            DESC="시스템 테이블에 DBA만 접근 가능"
        else
            RES="N"
            DESC="일반 사용자에게 시스템 테이블 접근 권한 존재"
        fi

    output_checkpoint "$CODE" "$CAT" "$NAME" "$IMP" "$STD" "$RES" "$DESC" "$DT"
}

check12() {
    local CODE="D-12"
    local CAT="접근관리"
    local NAME="안전한 리스너 비밀번호 설정 및 사용"
    local IMP="상"
    local STD="Listener의 비밀번호가 설정된 경우"
    local RES=""
    local DESC=""
    local DT=""

    # 버전 파싱 (예: 12.2.0.1.0 -> 주버전=12, 부버전=2)
    local VERSION_MAJOR=$(echo "$ORACLE_VERSION" | cut -d'.' -f1)
    local VERSION_MINOR=$(echo "$ORACLE_VERSION" | cut -d'.' -f2)
    VERSION_MAJOR=${VERSION_MAJOR:-0}
    VERSION_MINOR=${VERSION_MINOR:-0}

    local LISTENER_FILE="$ORACLE_HOME/network/admin/listener.ora"
    local PW_SETTING=""
    local ADMIN_RESTRICT=""

    if [ -f "$LISTENER_FILE" ]; then
        PW_SETTING=$(grep -i "PASSWORDS_" "$LISTENER_FILE" 2>/dev/null)
        ADMIN_RESTRICT=$(grep -i "ADMIN_RESTRICTIONS" "$LISTENER_FILE" 2>/dev/null)
    fi

    DT="[Oracle Version]\n$ORACLE_VERSION\n\n[listener.ora 비밀번호 설정]\n$PW_SETTING\n\n[ADMIN_RESTRICTIONS 설정]\n$ADMIN_RESTRICT"

    # 12.2 이상 버전 체크 (12c R2 = 12.2.x)
    local IS_12_2_OR_HIGHER=0
    if [ "$VERSION_MAJOR" -gt 12 ] 2>/dev/null; then
        IS_12_2_OR_HIGHER=1
    elif [ "$VERSION_MAJOR" -eq 12 ] && [ "$VERSION_MINOR" -ge 2 ] 2>/dev/null; then
        IS_12_2_OR_HIGHER=1
    fi

    if [ "$IS_12_2_OR_HIGHER" -eq 1 ]; then
        # 12c R2(12.2) 이상에서는 리스너 비밀번호 미지원
        # ADMIN_RESTRICTIONS_<listener_name>=ON 설정만 확인
        if echo "$ADMIN_RESTRICT" | grep -qi "ON"; then
            RES="Y"
            DESC="ADMIN_RESTRICTIONS가 ON으로 설정됨 (12.2+ 권장 설정)"
        else
            RES="N/A"
            DESC="12.2 이상 버전에서는 리스너 비밀번호 미지원 (ADMIN_RESTRICTIONS 권장)"
            DT="$DT\n\n[참고]\n12c R2(12.2) 이상에서는 리스너 비밀번호가 더 이상 지원되지 않습니다.\nADMIN_RESTRICTIONS_<listener_name>=ON 설정을 권장합니다."
        fi
    elif [ "$VERSION_MAJOR" -ge 12 ] 2>/dev/null; then
        # 12c R1 (12.1.x)
        if echo "$ADMIN_RESTRICT" | grep -qi "ON"; then
            RES="Y"
            DESC="ADMIN_RESTRICTIONS가 ON으로 설정됨 (12c 권장 설정)"
        else
            RES="N"
            DESC="ADMIN_RESTRICTIONS가 설정되지 않음"
        fi
    else
        # 11g 이하
        if [ -n "$PW_SETTING" ]; then
            RES="Y"
            DESC="리스너 비밀번호가 설정됨"
        else
            RES="N"
            DESC="리스너 비밀번호가 설정되지 않음"
        fi
    fi

    output_checkpoint "$CODE" "$CAT" "$NAME" "$IMP" "$STD" "$RES" "$DESC" "$DT"
}

check13() {
    local CODE="D-13"
    local CAT="접근관리"
    local NAME="불필요한 ODBC/OLE-DB 데이터 소스와 드라이브를 제거하여 사용"
    local IMP="중"
    local STD="불필요한 ODBC/OLE-DB가 설치되지 않은 경우"
    local RES=""
    local DESC=""
    local DT=""

    local RES="N/A"
    local DESC="Windows MSSQL 점검 항목으로 Oracle Linux 환경에서는 해당 없음"
    DT="Oracle Linux 환경 — 해당 없음"

    output_checkpoint "$CODE" "$CAT" "$NAME" "$IMP" "$STD" "$RES" "$DESC" "$DT"
}

check14() {
    local CODE="D-14"
    local CAT="접근관리"
    local NAME="데이터베이스의 주요 설정 파일, 비밀번호 파일 등과 같은 주요 파일들의 접근 권한이 적절하게 설정"
    local IMP="중"
    local STD="주요 설정 파일 및 디렉터리의 권한 설정 시 일반 사용자의 수정 권한을 제거한 경우"
    local RES=""
    local DESC=""
    local DT=""

    local CHECKED_FILES=""
    local VULNERABLE_FILES=""

    # 파일 권한 체크 함수
    # SUID/SGID/Sticky 비트(4000, 2000, 1000)를 제외하고 기본 권한만 비교
    # 예: 6751 -> 751, 4755 -> 755
    check_file_perm() {
        local file="$1"
        local max_perm="$2"
        if [ -f "$file" ] || [ -d "$file" ]; then
            local full_perm=$(stat -c "%a" "$file" 2>/dev/null)
            local owner=$(stat -c "%U:%G" "$file" 2>/dev/null)

            # 기본 권한만 추출 (마지막 3자리)
            # 예: 6751 -> 751, 4755 -> 755, 755 -> 755
            local base_perm
            if [ ${#full_perm} -gt 3 ]; then
                base_perm=${full_perm: -3}
            else
                base_perm=$full_perm
            fi

            CHECKED_FILES="${CHECKED_FILES}${file}: ${full_perm} (${owner})\n"

            # 기본 권한이 최대 허용치보다 큰 경우에만 취약
            if [ "$base_perm" -gt "$max_perm" ] 2>/dev/null; then
                VULNERABLE_FILES="${VULNERABLE_FILES}${file}: ${full_perm} (기본권한: ${base_perm}, 권장: ${max_perm} 이하)\n"
            fi
        fi
    }

    for f in $ORACLE_HOME/dbs/init*.ora; do
        [ -f "$f" ] && check_file_perm "$f" 640
    done

    for f in $ORACLE_HOME/dbs/orapw*; do
        [ -f "$f" ] && check_file_perm "$f" 640
    done

    check_file_perm "$ORACLE_HOME/network/admin/listener.ora" 755
    check_file_perm "$ORACLE_HOME/network/admin/sqlnet.ora" 755
    check_file_perm "$ORACLE_HOME/network/admin/tnsnames.ora" 644
    check_file_perm "$ORACLE_HOME/network" 755
    check_file_perm "$ORACLE_HOME/lib" 755

    for bin in oracle sqlplus sqlldr exp imp tkprof tnsping wrap; do
        check_file_perm "$ORACLE_HOME/bin/$bin" 755
    done

    for bin in lsnrctl dbsnmp; do
        check_file_perm "$ORACLE_HOME/bin/$bin" 750
    done

    if [ -z "$CHECKED_FILES" ]; then
        RES="N/A"
        DESC="점검 대상 파일을 찾을 수 없음"
        DT="[확인된 파일 없음]\nORACLE_HOME: $ORACLE_HOME"
    elif [ -z "$VULNERABLE_FILES" ]; then
        RES="Y"
        DESC="주요 설정 파일의 권한이 적절하게 설정됨"
        DT="[파일 권한 현황]\n$CHECKED_FILES"
    else
        RES="N"
        DESC="주요 설정 파일의 권한이 과도하게 부여됨"
        DT="[취약 파일]\n$VULNERABLE_FILES\n[전체 파일]\n$CHECKED_FILES"
    fi

    output_checkpoint "$CODE" "$CAT" "$NAME" "$IMP" "$STD" "$RES" "$DESC" "$DT"
}

check15() {
    local CODE="D-15"
    local CAT="접근관리"
    local NAME="관리자 이외의 사용자가 오라클 리스너의 접속을 통해 리스너 로그 및 trace 파일에 대한 변경 제한"
    local IMP="하"
    local STD="Listener 관련 설정 파일에 대한 권한이 관리자로 설정되어 있으며, Listener로 파라미터를 변경할 수 없게 옵션이 설정된 경우"
    local RES=""
    local DESC=""
    local DT=""

    local LISTENER_FILE=""
    local LISTENER_PATH_SOURCE=""

    # 1. TNS_ADMIN 환경변수 우선 확인
    if [ -n "$TNS_ADMIN" ] && [ -f "$TNS_ADMIN/listener.ora" ]; then
        LISTENER_FILE="$TNS_ADMIN/listener.ora"
        LISTENER_PATH_SOURCE="TNS_ADMIN 환경변수"
    # 2. lsnrctl status에서 실제 경로 파싱 시도
    elif command -v lsnrctl &>/dev/null; then
        # lsnrctl status 출력에서 Listener Parameter File 경로 추출
        local LSNR_STATUS=$($ORACLE_HOME/bin/lsnrctl status 2>/dev/null || lsnrctl status 2>/dev/null)
        local LSNR_PARAM_FILE=$(echo "$LSNR_STATUS" | grep -i "Listener Parameter File" | sed 's/.*Listener Parameter File[[:space:]]*//;s/[[:space:]]*$//')
        if [ -n "$LSNR_PARAM_FILE" ] && [ -f "$LSNR_PARAM_FILE" ]; then
            LISTENER_FILE="$LSNR_PARAM_FILE"
            LISTENER_PATH_SOURCE="lsnrctl status"
        fi
    fi

    # 3. 기본 경로 fallback
    if [ -z "$LISTENER_FILE" ] && [ -f "$ORACLE_HOME/network/admin/listener.ora" ]; then
        LISTENER_FILE="$ORACLE_HOME/network/admin/listener.ora"
        LISTENER_PATH_SOURCE="ORACLE_HOME 기본 경로"
    fi

    local ADMIN_RESTRICT=""

    if [ -n "$LISTENER_FILE" ] && [ -f "$LISTENER_FILE" ]; then
        ADMIN_RESTRICT=$(grep -i "ADMIN_RESTRICTIONS" "$LISTENER_FILE" 2>/dev/null)
        local FILE_PERM=$(ls -la "$LISTENER_FILE" 2>/dev/null)
        DT="[listener.ora 경로]\n$LISTENER_FILE (출처: $LISTENER_PATH_SOURCE)\n\n[listener.ora 파일 권한]\n$FILE_PERM\n\n[ADMIN_RESTRICTIONS 설정]\n$ADMIN_RESTRICT"
    else
        DT="[listener.ora 파일을 찾을 수 없음]\n검색 경로:\n- TNS_ADMIN: ${TNS_ADMIN:-미설정}\n- ORACLE_HOME/network/admin: $ORACLE_HOME/network/admin"
        RES="N/A"
        DESC="listener.ora 파일을 찾을 수 없음"
        return
    fi

    if echo "$ADMIN_RESTRICT" | grep -qi "ON"; then
        RES="Y"
        DESC="ADMIN_RESTRICTIONS가 ON으로 설정됨"
    else
        RES="N"
        DESC="ADMIN_RESTRICTIONS가 설정되지 않음"
    fi

    output_checkpoint "$CODE" "$CAT" "$NAME" "$IMP" "$STD" "$RES" "$DESC" "$DT"
}

check16() {
    local CODE="D-16"
    local CAT="접근관리"
    local NAME="Windows 인증 모드 사용"
    local IMP="하"
    local STD="Windows 인증 모드를 사용하고 sa 계정이 비활성화되어 있는 경우 sa 계정 활성화 시 강력한 암호 정책을 설정한 경우"
    local RES=""
    local DESC=""
    local DT=""

    local RES="N/A"
    local DESC="Oracle은 Windows 인증 모드가 없음 (MSSQL 전용)"
    local DT="[참고]\nWindows 인증 모드는 Microsoft SQL Server 전용 기능입니다.\nOracle은 자체 인증 메커니즘(비밀번호 인증, OS 인증, Kerberos 등)을 사용합니다.\n\nOracle의 OS 인증은 OS_AUTHENT_PREFIX 파라미터와 REMOTE_OS_AUTHENT 파라미터로 제어됩니다.\n이 점검 항목은 MSSQL에만 해당됩니다."

    output_checkpoint "$CODE" "$CAT" "$NAME" "$IMP" "$STD" "$RES" "$DESC" "$DT"
}

check17() {
    local CODE="D-17"
    local CAT="옵션관리"
    local NAME="Audit Table은 데이터베이스 관리자 계정으로 접근하도록 제한"
    local IMP="하"
    local STD="Audit Table 접근 권한이 관리자 계정으로 설정한 경우"
    local RES=""
    local DESC=""
    local DT=""

        local AUD_OWNER=$(echo "
    SELECT owner FROM dba_tables WHERE table_name = 'AUD\$';
    " | $SQLPLUS_CMD 2>/dev/null | grep -v "^OWNER" | grep -v "^-" | grep -v "^$" | head -1)

        local AUD_PRIVS=$(echo "
    SET LINESIZE 200
    SELECT grantee, privilege FROM dba_tab_privs WHERE table_name = 'AUD\$';
    " | $SQLPLUS_CMD 2>/dev/null)

        DT="[AUD\$ 테이블 소유자]\n$AUD_OWNER\n\n[AUD\$ 테이블 접근 권한]\n$AUD_PRIVS"

        if [ "$AUD_OWNER" == "SYS" ]; then
            RES="Y"
            DESC="Audit Table이 SYS 소유로 설정됨"
        else
            RES="N"
            DESC="Audit Table 소유자가 SYS가 아님"
        fi

    output_checkpoint "$CODE" "$CAT" "$NAME" "$IMP" "$STD" "$RES" "$DESC" "$DT"
}

check18() {
    local CODE="D-18"
    local CAT="옵션관리"
    local NAME="응용프로그램 또는 DBA 계정의 Role이 Public으로 설정되지 않도록 조정"
    local IMP="상"
    local STD="DBA 계정의 Role이 Public으로 설정되지 않은 경우"
    local RES=""
    local DESC=""
    local DT=""

        local PUBLIC_ROLES=$(echo "
    SET LINESIZE 200
    SELECT granted_role FROM dba_role_privs WHERE grantee = 'PUBLIC';
    " | $SQLPLUS_CMD 2>/dev/null)

        local PUBLIC_PRIVS=$(echo "
    SELECT privilege FROM dba_sys_privs WHERE grantee = 'PUBLIC';
    " | $SQLPLUS_CMD 2>/dev/null)

        DT="[PUBLIC에 부여된 Role]\n$PUBLIC_ROLES\n\n[PUBLIC에 부여된 시스템 권한]\n$PUBLIC_PRIVS"

        local DANGER_PRIVS_RAW=$(echo "
    SET HEADING OFF
    SET FEEDBACK OFF
    SET PAGESIZE 0
    SELECT COUNT(*) FROM dba_sys_privs
    WHERE grantee = 'PUBLIC'
    AND privilege IN ('CREATE SESSION', 'CREATE TABLE', 'CREATE VIEW', 'CREATE PROCEDURE',
    'ALTER SYSTEM', 'DROP ANY TABLE', 'DELETE ANY TABLE');
    " | $SQLPLUS_CMD 2>/dev/null)
        # 숫자만 추출 (공백, 줄바꿈 제거)
        local DANGER_PRIVS=$(echo "$DANGER_PRIVS_RAW" | tr -d '[:space:]' | grep -oE '^[0-9]+' | head -1)
        DANGER_PRIVS=${DANGER_PRIVS:-0}

        if [ "$DANGER_PRIVS" -eq 0 ] 2>/dev/null; then
            RES="Y"
            DESC="PUBLIC에 위험한 권한이 부여되지 않음"
        else
            RES="N"
            DESC="PUBLIC에 위험한 권한이 부여됨"
        fi

    output_checkpoint "$CODE" "$CAT" "$NAME" "$IMP" "$STD" "$RES" "$DESC" "$DT"
}

check19() {
    local CODE="D-19"
    local CAT="옵션관리"
    local NAME="OS_ROLES, REMOTE_OS_AUTHENTICATION, REMOTE_OS_ROLES를 FALSE로 설정"
    local IMP="상"
    local STD="OS_ROLES, REMOTE_OS_AUTHENTICATION, REMOTE_OS_ROLES 설정이 FALSE로 설정된 경우"
    local RES=""
    local DESC=""
    local DT=""

        local OS_PARAMS=$(echo "
    SET LINESIZE 200
    SELECT name, value FROM v\$parameter
    WHERE name IN ('os_roles', 'remote_os_authent', 'remote_os_roles');
    " | $SQLPLUS_CMD 2>/dev/null)

        DT="[OS 관련 파라미터]\n$OS_PARAMS"

        local TRUE_COUNT_RAW=$(echo "
    SET HEADING OFF
    SET FEEDBACK OFF
    SET PAGESIZE 0
    SELECT COUNT(*) FROM v\$parameter
    WHERE name IN ('os_roles', 'remote_os_authent', 'remote_os_roles')
    AND UPPER(value) = 'TRUE';
    " | $SQLPLUS_CMD 2>/dev/null)
        # 숫자만 추출 (공백, 줄바꿈 제거)
        local TRUE_COUNT=$(echo "$TRUE_COUNT_RAW" | tr -d '[:space:]' | grep -oE '^[0-9]+' | head -1)
        TRUE_COUNT=${TRUE_COUNT:-0}

        if [ "$TRUE_COUNT" -eq 0 ] 2>/dev/null; then
            RES="Y"
            DESC="OS_ROLES, REMOTE_OS_AUTHENT, REMOTE_OS_ROLES가 모두 FALSE"
        else
            RES="N"
            DESC="OS 관련 파라미터 중 TRUE로 설정된 항목 존재"
        fi

    output_checkpoint "$CODE" "$CAT" "$NAME" "$IMP" "$STD" "$RES" "$DESC" "$DT"
}

check20() {
    local CODE="D-20"
    local CAT="옵션관리"
    local NAME="인가되지 않은 Object Owner의 제한"
    local IMP="하"
    local STD="Object Owner가 SYS, SYSTEM, 관리자 계정 등으로 제한된 경우"
    local RES=""
    local DESC=""
    local DT=""

        local RES="M"
        local DESC="Object Owner 목록 수동 확인 필요"

        local OBJECT_OWNERS=$(echo "
    SET LINESIZE 200
    SELECT DISTINCT owner FROM dba_objects
    WHERE owner NOT IN ('SYS', 'SYSTEM', 'MDSYS', 'CTXSYS', 'ORDSYS', 'ORDPLUGINS',
    'AURORA\$JIS\$UTILITY\$', 'HR', 'ODM', 'ODM_MTR', 'OE', 'OLAPSYS', 'OUTLN',
    'LBACSYS', 'PUBLIC', 'DBSNMP', 'RMAN', 'WKSYS', 'WMSYS', 'XDB', 'EXFSYS',
    'SYSMAN', 'ORDDATA', 'APEX_040000', 'APEX_030200', 'FLOWS_FILES')
    AND owner NOT IN (SELECT grantee FROM dba_role_privs WHERE granted_role = 'DBA')
    ORDER BY owner;
    " | $SQLPLUS_CMD 2>/dev/null)

        DT="[비표준 Object Owner 목록 - 확인 필요]\n$OBJECT_OWNERS"

    output_checkpoint "$CODE" "$CAT" "$NAME" "$IMP" "$STD" "$RES" "$DESC" "$DT"
}

check21() {
    local CODE="D-21"
    local CAT="옵션관리"
    local NAME="인가되지 않은 GRANT OPTION 사용 제한"
    local IMP="중"
    local STD="WITH_GRANT_OPTION이 ROLE에 의하여 설정된 경우"
    local RES=""
    local DESC=""
    local DT=""

        local GRANT_OPTION=$(echo "
    SET LINESIZE 200
    SELECT grantee || ':' || owner || '.' || table_name AS grant_info
    FROM dba_tab_privs
    WHERE grantable = 'YES'
    AND owner NOT IN ('SYS', 'MDSYS', 'ORDPLUGINS', 'ORDSYS', 'SYSTEM', 'WMSYS', 'LBACSYS')
    AND grantee NOT IN (SELECT grantee FROM dba_role_privs WHERE granted_role = 'DBA')
    ORDER BY grantee;
    " | $SQLPLUS_CMD 2>/dev/null)

        DT="[WITH GRANT OPTION 보유 계정]\n$GRANT_OPTION"

        local GRANT_COUNT=$(echo "$GRANT_OPTION" | grep -v "^GRANT_INFO" | grep -v "^-" | grep -v "^$" | grep -v "no rows" | wc -l)

        if [ "$GRANT_COUNT" -eq 0 ]; then
            RES="Y"
            DESC="비인가 계정에 GRANT OPTION이 부여되지 않음"
        else
            RES="N"
            DESC="비인가 계정에 GRANT OPTION이 부여됨"
        fi

    output_checkpoint "$CODE" "$CAT" "$NAME" "$IMP" "$STD" "$RES" "$DESC" "$DT"
}

check22() {
    local CODE="D-22"
    local CAT="옵션관리"
    local NAME="데이터베이스의 자원 제한 기능을 TRUE로 설정"
    local IMP="하"
    local STD="RESOURCE_LIMIT 설정이 TRUE로 되어있는 경우"
    local RES=""
    local DESC=""
    local DT=""

        local RESOURCE_LIMIT=$(echo "
    SELECT value FROM v\$parameter WHERE name = 'resource_limit';
    " | $SQLPLUS_CMD 2>/dev/null | grep -v "^VALUE" | grep -v "^-" | grep -v "^$" | head -1)

        DT="[RESOURCE_LIMIT 설정]\n$RESOURCE_LIMIT"

        if [ "$RESOURCE_LIMIT" == "TRUE" ]; then
            RES="Y"
            DESC="RESOURCE_LIMIT이 TRUE로 설정됨"
        else
            RES="N"
            DESC="RESOURCE_LIMIT이 FALSE로 설정됨"
        fi

    output_checkpoint "$CODE" "$CAT" "$NAME" "$IMP" "$STD" "$RES" "$DESC" "$DT"
}

check23() {
    local CODE="D-23"
    local CAT="옵션관리"
    local NAME="xp_cmdshell 사용 제한"
    local IMP="상"
    local STD="xp_cmdshell이 비활성화 되어 있거나, 활성화 되어 있으면 다음의 조건을 모두 만족하는 경우 1. public의 실행(Execute) 권한이 부여되어 있지 않은 경우 2. 서비스 계정(애플리케이션 연동)에 sysadmin 권한이 부여되어 있지 않은 경우"
    local RES=""
    local DESC=""
    local DT=""

    local RES="N/A"
    local DESC="Oracle은 xp_cmdshell이 없음 (MSSQL 전용)"
    local DT="[참고]\nxp_cmdshell은 Microsoft SQL Server에서 운영체제 명령을 실행하는 확장 저장 프로시저입니다.\nOracle은 xp_cmdshell 기능을 지원하지 않습니다.\n\nOracle에서 OS 명령 실행이 필요한 경우 DBMS_SCHEDULER나 외부 프로시저(extproc)를 사용합니다.\n이 점검 항목은 MSSQL에만 해당됩니다."

    output_checkpoint "$CODE" "$CAT" "$NAME" "$IMP" "$STD" "$RES" "$DESC" "$DT"
}

check24() {
    local CODE="D-24"
    local CAT="옵션관리"
    local NAME="Registry Procedure 권한 제한"
    local IMP="상"
    local STD="제한이 필요한 시스템 확장 저장 프로시저들이 DBA 외 guest/public에게 부여되지 않은 경우"
    local RES=""
    local DESC=""
    local DT=""

    local RES="N/A"
    local DESC="Oracle은 Registry Procedure가 없음 (MSSQL 전용)"
    local DT="[참고]\nRegistry Stored Procedure(xp_regread, xp_regwrite 등)는 Microsoft SQL Server에서\nWindows 레지스트리를 읽고 쓰는 확장 저장 프로시저입니다.\n\nOracle은 Windows 레지스트리 접근 기능을 제공하지 않습니다.\n이 점검 항목은 MSSQL에만 해당됩니다."

    output_checkpoint "$CODE" "$CAT" "$NAME" "$IMP" "$STD" "$RES" "$DESC" "$DT"
}

check25() {
    local CODE="D-25"
    local CAT="패치관리"
    local NAME="주기적 보안 패치 및 벤더 권고 사항 적용"
    local IMP="상"
    local STD="보안 패치가 적용된 버전을 사용하는 경우"
    local RES=""
    local DESC=""
    local DT=""

        local RES="M"
        local DESC="현재 버전 확인 후 최신 패치 적용 여부 수동 확인 필요"

        local PATCH_INFO=$(echo "
    SET LINESIZE 200
    SELECT * FROM dba_registry_sqlpatch ORDER BY install_id DESC;
    " | $SQLPLUS_CMD 2>/dev/null)

        DT="[현재 버전]\n$DB_VERSION\n\n[설치된 패치]\n$PATCH_INFO\n\n※ 최신 버전은 Oracle 공식 사이트에서 확인\nhttps://www.oracle.com/security-alerts/"

    output_checkpoint "$CODE" "$CAT" "$NAME" "$IMP" "$STD" "$RES" "$DESC" "$DT"
}

check26() {
    local CODE="D-26"
    local CAT="패치관리"
    local NAME="데이터베이스의 접근, 변경, 삭제 등의 감사 기록이 기관의 감사 기록 정책에 적합하도록 설정"
    local IMP="상"
    local STD="DBMS의 감사 로그 저장 정책이 수립되어 있으며, 정책 설정이 적용된 경우"
    local RES=""
    local DESC=""
    local DT=""

        local AUDIT_TRAIL=$(echo "
    SELECT value FROM v\$parameter WHERE name = 'audit_trail';
    " | $SQLPLUS_CMD 2>/dev/null | grep -v "^VALUE" | grep -v "^-" | grep -v "^$" | head -1)

        local AUDIT_POLICY=$(echo "
    SET LINESIZE 200
    SELECT audit_option, success, failure FROM dba_stmt_audit_opts;
    " | $SQLPLUS_CMD 2>/dev/null)

        DT="[AUDIT_TRAIL 설정]\n$AUDIT_TRAIL\n\n[감사 정책]\n$AUDIT_POLICY"

        if [ "$AUDIT_TRAIL" == "NONE" ] || [ -z "$AUDIT_TRAIL" ]; then
            RES="N"
            DESC="감사 로그(AUDIT_TRAIL)가 비활성화됨"
        else
            RES="Y"
            DESC="감사 로그가 활성화됨 (AUDIT_TRAIL=$AUDIT_TRAIL)"
        fi

    output_checkpoint "$CODE" "$CAT" "$NAME" "$IMP" "$STD" "$RES" "$DESC" "$DT"
}


#================================================================
# EXECUTE
#================================================================

echo ""
echo "  $META_PLAT Security Assessment v$META_VER [$META_STD]"
echo "  ─────────────────────────────────────────────────────────"
echo ""
echo "  호스트: $SYS_HOST"
echo "  DBMS: $META_PLAT $DB_VERSION"
echo ""
echo "  [진단 시작]"
echo "  ─────────────────────────────────────────────────────────"
echo ""

# XML 헤더
cat > "$OUTPUT_FILE" << XMLEOF
<?xml version="1.0" encoding="UTF-8"?>
<seedgen>
    <meta>
        <date>$META_DATE</date>
        <ver>$META_VER</ver>
        <plat>$META_PLAT</plat>
        <type>$META_TYPE</type>
        <std>$META_STD</std>
    </meta>
    <sys>
        <host>$SYS_HOST</host>
        <dom>$SYS_DOM</dom>
        <os>
            <n>$META_PLAT $DB_VERSION</n>
            <fn>$META_PLAT</fn>
        </os>
        <kn>$DB_VERSION</kn>
        <arch>$(uname -m)</arch>
        <net>
            <ip>${DB_HOST:-localhost}</ip>
            <all><![CDATA[Host: ${DB_HOST:-localhost}, Port: ${DB_PORT:-N/A}]]></all>
        </net>
    </sys>
    <results>
XMLEOF

# 진단 실행
    check01
    check02
    check03
    check04
    check05
    check06
    check07
    check08
    check09
    check10
    check11
    check12
    check13
    check14
    check15
    check16
    check17
    check18
    check19
    check20
    check21
    check22
    check23
    check24
    check25
    check26

# XML 종료
cat >> "$OUTPUT_FILE" << XMLEOF
    </results>
</seedgen>
XMLEOF

#================================================================
# CLEANUP
#================================================================
echo ""
echo "  ─────────────────────────────────────────────────────────"
echo ""
echo "  점검이 완료되었습니다!"
echo "  호스트: $SYS_HOST"
echo "  결과 파일: $OUTPUT_FILE"
echo ""

#================================================================
# Oracle_Linux 보안 진단 스크립트
# KISA 주요정보통신기반시설 기술적 취약점 분석·평가 기준
#================================================================
# 버전  : 2603070
# 대상  : Oracle_Linux
# 항목  : D-01 ~ D-26 (26개)
# 제작  : Seedgen
#================================================================
META_STD="KISA"

#================================================================
# INIT
#================================================================
META_VER="1.0"
META_PLAT="Oracle"
META_TYPE="DBMS"

# XML 특수문자 이스케이프
xml_escape() {
    local s="$1"
    s="${s//&/&amp;}"
    s="${s//</&lt;}"
    s="${s//>/&gt;}"
    s="${s//\"/&quot;}"
    echo "$s"
}

# 결과 출력 함수
output_checkpoint() {
    local CODE="$1"
    local CAT="$2"
    local NAME="$3"
    local IMP="$4"
    local STD="$5"
    local RES="$6"
    local DESC="$7"
    local DT="$8"

    case "$RES" in
        "Y")   echo -e "    [\033[32mY\033[0m] $CODE $NAME" ;;
        "N")   echo -e "    [\033[31mN\033[0m] $CODE $NAME" ;;
        "M")   echo -e "    [\033[33mM\033[0m] $CODE $NAME" ;;
        "N/A") echo -e "    [\033[90m-\033[0m] $CODE $NAME" ;;
        *)     echo -e "    [-] $CODE $NAME" ;;
    esac

    local E_NAME; E_NAME=$(xml_escape "$NAME")
    local E_DESC; E_DESC=$(xml_escape "$DESC")
    local E_STD; E_STD=$(xml_escape "$STD")
    cat >> "$OUTPUT_FILE" << CPEOF
        <cp>
            <code>$CODE</code>
            <cat>$CAT</cat>
            <n>$E_NAME</n>
            <imp>$IMP</imp>
            <std>$E_STD</std>
            <res>$RES</res>
            <desc>$E_DESC</desc>
            <dt><![CDATA[$DT]]></dt>
        </cp>
CPEOF
}

#================================================================
# CONNECT — 플랫폼별 커스터마이즈 영역
# (클라이언트 확인, 연결정보 입력, 연결 테스트, 버전 변수 세팅)
#================================================================

# SQL 실행 함수
run_sql() {
    local SQL="$1"
    echo "$SQL" | $SQLPLUS_CMD 2>/dev/null | grep -v "^$" | grep -v "^SQL>" | grep -v "^Connected" | grep -v "rows selected"
}

echo ""
echo "============================================================"
echo " Oracle DB 보안 진단 스크립트"
echo "============================================================"
echo ""
echo "[연결 정보 입력]"
echo ""

# ORACLE_HOME 확인
if [ -z "$ORACLE_HOME" ]; then
    echo -n "ORACLE_HOME Path: "
    read ORACLE_HOME
    if [ ! -d "$ORACLE_HOME" ]; then
        echo "[!] ORACLE_HOME 디렉터리를 찾을 수 없습니다."
        exit 1
    fi
    export ORACLE_HOME
fi

# sqlplus 클라이언트 확인
SQLPLUS_BIN="$ORACLE_HOME/bin/sqlplus"
if [ ! -x "$SQLPLUS_BIN" ]; then
    SQLPLUS_BIN=$(which sqlplus 2>/dev/null)
    if [ -z "$SQLPLUS_BIN" ]; then
        echo "[!] sqlplus를 찾을 수 없습니다."
        exit 1
    fi
fi

# 연결 정보 입력
echo -n "User (default: sys): "
read DB_USER
DB_USER=${DB_USER:-sys}

echo -n "Password: "
read -s DB_PASS
echo ""

if [ -z "$DB_PASS" ]; then
    echo "[!] 비밀번호를 입력해주세요."
    exit 1
fi

echo -n "SID (default: orcl): "
read DB_SID
DB_SID=${DB_SID:-orcl}

echo -n "Connect as SYSDBA? (y/n, default: y): "
read AS_SYSDBA
AS_SYSDBA=${AS_SYSDBA:-y}

# Oracle 연결 명령어 구성
if [ "$AS_SYSDBA" == "y" ] || [ "$AS_SYSDBA" == "Y" ]; then
    SQLPLUS_CMD="$SQLPLUS_BIN -S $DB_USER/$DB_PASS@$DB_SID as sysdba"
else
    SQLPLUS_CMD="$SQLPLUS_BIN -S $DB_USER/$DB_PASS@$DB_SID"
fi

# 연결 테스트
echo ""
echo "[연결 테스트 중...]"
DB_VERSION=$(echo "SELECT banner FROM v\$version WHERE ROWNUM = 1;" | $SQLPLUS_CMD 2>/dev/null | grep -i "Oracle" | head -1)
if [ -z "$DB_VERSION" ]; then
    echo "[!] Oracle 연결 실패"
    exit 1
fi
echo "[OK] $DB_VERSION 연결 성공"
echo ""

# Oracle 버전 정보
ORACLE_VERSION=$(echo "SELECT version FROM v\$instance;" | $SQLPLUS_CMD 2>/dev/null | grep -E "^[0-9]" | head -1)

#================================================================
# COLLECT
#================================================================
META_DATE=$(date +%Y-%m-%dT%H:%M:%S%:z)
SYS_HOST=$(hostname)
SYS_DOM=$(hostname -d 2>/dev/null || echo "N/A")
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
OUTPUT_FILE="${SCRIPT_DIR}/${META_PLAT}_${SYS_HOST}_$(date +%Y%m%d_%H%M%S).xml"

#================================================================
# CHECK FUNCTIONS
#================================================================

check01() {
    local CODE="D-01"
    local CAT="계정관리"
    local NAME="기본 계정의 비밀번호, 정책 등을 변경하여 사용"
    local IMP="상"
    local STD="기본 계정의 초기 비밀번호를 변경하거나 잠금설정한 경우"
    local RES=""
    local DESC=""
    local DT=""

        # 12c+ 추가 기본 계정 포함
        local DEFAULT_ACCOUNTS=$(echo "
    SET LINESIZE 200
    SET PAGESIZE 100
    SELECT username, account_status, profile FROM dba_users
    WHERE username IN ('SCOTT', 'SYSTEM', 'SYS', 'DBSNMP', 'OUTLN', 'HR', 'OE', 'PM', 'SH',
        'ANONYMOUS', 'APEX_PUBLIC_USER', 'FLOWS_FILES', 'APEX_040000', 'APEX_040200',
        'XDB', 'CTXSYS', 'MDSYS', 'ORDSYS', 'EXFSYS', 'WMSYS', 'OLAPSYS', 'ORDDATA',
        'ORDPLUGINS', 'SI_INFORMTN_SCHEMA', 'SYSMAN', 'MGMT_VIEW', 'OWBSYS', 'OWBSYS_AUDIT',
        'APPQOSSYS', 'GSMADMIN_INTERNAL', 'GSMCATUSER', 'GSMUSER', 'SYSBACKUP', 'SYSDG',
        'SYSKM', 'SYSRAC', 'SYS\$UMF', 'AUDSYS', 'DBSFWUSER', 'GGSYS', 'DIP', 'REMOTE_SCHEDULER_AGENT');
    " | $SQLPLUS_CMD 2>/dev/null)

        # SYS, SYSTEM 제외하고 활성화된 기본 계정 체크 (12c+ 추가 계정 포함)
        local OPEN_DEFAULT=$(echo "
    SELECT username FROM dba_users
    WHERE username IN ('SCOTT', 'DBSNMP', 'OUTLN', 'HR', 'OE', 'PM', 'SH',
        'ANONYMOUS', 'APEX_PUBLIC_USER', 'FLOWS_FILES', 'APEX_040000', 'APEX_040200',
        'XDB', 'CTXSYS', 'MDSYS', 'ORDSYS', 'EXFSYS', 'WMSYS', 'OLAPSYS', 'ORDDATA',
        'ORDPLUGINS', 'SI_INFORMTN_SCHEMA', 'SYSMAN', 'MGMT_VIEW', 'OWBSYS', 'OWBSYS_AUDIT',
        'APPQOSSYS', 'GSMADMIN_INTERNAL', 'GSMCATUSER', 'GSMUSER', 'SYSBACKUP', 'SYSDG',
        'SYSKM', 'SYSRAC', 'AUDSYS', 'DBSFWUSER', 'GGSYS', 'DIP', 'REMOTE_SCHEDULER_AGENT')
    AND account_status = 'OPEN';
    " | $SQLPLUS_CMD 2>/dev/null | grep -v "^USERNAME" | grep -v "^-" | grep -v "^$" | grep -v "no rows")

        DT="[기본 계정 상태]\n$DEFAULT_ACCOUNTS"

        if [ -z "$OPEN_DEFAULT" ]; then
            RES="Y"
            DESC="기본 계정이 잠금 설정되어 있음"
        else
            RES="N"
            DESC="활성화된 기본 계정 존재"
            DT="[활성화된 기본 계정]\n$OPEN_DEFAULT\n\n$DT"
        fi

    output_checkpoint "$CODE" "$CAT" "$NAME" "$IMP" "$STD" "$RES" "$DESC" "$DT"
}

check02() {
    local CODE="D-02"
    local CAT="계정관리"
    local NAME="데이터베이스의 불필요 계정을 제거하거나, 잠금설정 후 사용"
    local IMP="상"
    local STD="계정 정보를 확인하여 불필요한 계정이 없는 경우"
    local RES=""
    local DESC=""
    local DT=""

        local RES="M"
        local DESC="계정 목록 수동 확인 필요"

        local ALL_ACCOUNTS=$(echo "
    SET LINESIZE 200
    SET PAGESIZE 100
    SELECT username, account_status, lock_date, expiry_date, profile
    FROM dba_users ORDER BY username;
    " | $SQLPLUS_CMD 2>/dev/null)

        DT="[계정 목록 - 불필요 계정 여부 확인 필요]\n$ALL_ACCOUNTS"

    output_checkpoint "$CODE" "$CAT" "$NAME" "$IMP" "$STD" "$RES" "$DESC" "$DT"
}

check03() {
    local CODE="D-03"
    local CAT="계정관리"
    local NAME="비밀번호 사용 기간 및 복잡도를 기관의 정책에 맞도록 설정"
    local IMP="상"
    local STD="기관 정책에 맞게 비밀번호 사용 기간 및 복잡도 설정이 적용된 경우"
    local RES=""
    local DESC=""
    local DT=""

        local PROFILE_POLICY=$(echo "
    SET LINESIZE 200
    SET PAGESIZE 100
    SELECT profile, resource_name, limit FROM dba_profiles
    WHERE resource_type = 'PASSWORD' ORDER BY profile, resource_name;
    " | $SQLPLUS_CMD 2>/dev/null)

        DT="[프로파일 비밀번호 정책]\n$PROFILE_POLICY"

        local VERIFY_FUNC=$(echo "
    SELECT profile, limit FROM dba_profiles
    WHERE resource_name = 'PASSWORD_VERIFY_FUNCTION' AND limit != 'NULL';
    " | $SQLPLUS_CMD 2>/dev/null | grep -v "^PROFILE" | grep -v "^-" | grep -v "^$" | grep -v "no rows")

        if [ -n "$VERIFY_FUNC" ]; then
            RES="Y"
            DESC="비밀번호 검증 함수가 설정됨"
        else
            RES="N"
            DESC="비밀번호 검증 함수(PASSWORD_VERIFY_FUNCTION)가 설정되지 않음"
        fi

    output_checkpoint "$CODE" "$CAT" "$NAME" "$IMP" "$STD" "$RES" "$DESC" "$DT"
}

check04() {
    local CODE="D-04"
    local CAT="계정관리"
    local NAME="데이터베이스 관리자 권한을 꼭 필요한 계정 및 그룹에 대해서만 허용"
    local IMP="상"
    local STD="관리자 권한이 필요한 계정 및 그룹에만 관리자 권한이 부여된 경우"
    local RES=""
    local DESC=""
    local DT=""

        local RES="M"
        local DESC="SYSDBA/DBA 권한 보유 계정 수동 확인 필요"

        local SYSDBA_USERS=$(echo "
    SET LINESIZE 200
    SELECT username FROM v\$pwfile_users WHERE SYSDBA = 'TRUE';
    " | $SQLPLUS_CMD 2>/dev/null)

        local DBA_USERS=$(echo "
    SELECT grantee FROM dba_role_privs WHERE granted_role = 'DBA';
    " | $SQLPLUS_CMD 2>/dev/null)

        local ADMIN_OPTION=$(echo "
    SELECT grantee, privilege FROM dba_sys_privs
    WHERE admin_option = 'YES'
    AND grantee NOT IN ('SYS', 'SYSTEM', 'DBA')
    AND grantee NOT IN (SELECT grantee FROM dba_role_privs WHERE granted_role = 'DBA');
    " | $SQLPLUS_CMD 2>/dev/null)

        DT="[SYSDBA 권한 보유 계정]\n$SYSDBA_USERS\n\n[DBA 롤 보유 계정]\n$DBA_USERS\n\n[Admin Option 보유 계정]\n$ADMIN_OPTION"

    output_checkpoint "$CODE" "$CAT" "$NAME" "$IMP" "$STD" "$RES" "$DESC" "$DT"
}

check05() {
    local CODE="D-05"
    local CAT="계정관리"
    local NAME="비밀번호 재사용에 대한 제약 설정"
    local IMP="중"
    local STD="비밀번호 재사용 제한 설정을 적용한 경우"
    local RES=""
    local DESC=""
    local DT=""

        local REUSE_POLICY=$(echo "
    SET LINESIZE 200
    SELECT profile, resource_name, limit FROM dba_profiles
    WHERE resource_name IN ('PASSWORD_REUSE_TIME', 'PASSWORD_REUSE_MAX');
    " | $SQLPLUS_CMD 2>/dev/null)

        DT="[비밀번호 재사용 정책]\n$REUSE_POLICY"

        local REUSE_SET_RAW=$(echo "
    SET HEADING OFF
    SET FEEDBACK OFF
    SET PAGESIZE 0
    SELECT COUNT(*) FROM dba_profiles
    WHERE resource_name IN ('PASSWORD_REUSE_TIME', 'PASSWORD_REUSE_MAX')
    AND limit != 'UNLIMITED' AND limit != 'DEFAULT';
    " | $SQLPLUS_CMD 2>/dev/null)
        # 숫자만 추출 (공백, 줄바꿈 제거)
        local REUSE_SET=$(echo "$REUSE_SET_RAW" | tr -d '[:space:]' | grep -oE '^[0-9]+' | head -1)
        REUSE_SET=${REUSE_SET:-0}

        if [ "$REUSE_SET" -gt 0 ] 2>/dev/null; then
            RES="Y"
            DESC="비밀번호 재사용 제한이 설정됨"
        else
            RES="N"
            DESC="비밀번호 재사용 제한이 설정되지 않음"
        fi

    output_checkpoint "$CODE" "$CAT" "$NAME" "$IMP" "$STD" "$RES" "$DESC" "$DT"
}

check06() {
    local CODE="D-06"
    local CAT="계정관리"
    local NAME="DB 사용자 계정을 개별적으로 부여하여 사용"
    local IMP="중"
    local STD="사용자별 계정을 사용하고 있는 경우"
    local RES=""
    local DESC=""
    local DT=""

        local RES="M"
        local DESC="사용자별 개별 계정 사용 여부 수동 확인 필요"

        local USER_LIST=$(echo "
    SET LINESIZE 200
    SELECT username, created, account_status FROM dba_users
    WHERE username NOT IN ('SYS', 'SYSTEM', 'ANONYMOUS', 'APEX_PUBLIC_USER', 'FLOWS_FILES',
    'APEX_040000', 'APEX_030200', 'OUTLN', 'XDB', 'CTXSYS', 'DBSNMP', 'MDSYS', 'ORDSYS',
    'EXFSYS', 'WMSYS', 'OLAPSYS', 'ORDDATA', 'ORDPLUGINS', 'SI_INFORMTN_SCHEMA', 'SYSMAN',
    'MGMT_VIEW', 'SCOTT', 'OWBSYS', 'OWBSYS_AUDIT', 'SPATIAL_CSW_ADMIN_USR', 'SPATIAL_WFS_ADMIN_USR')
    ORDER BY username;
    " | $SQLPLUS_CMD 2>/dev/null)

        DT="[사용자 계정 목록 - 개별 계정 사용 여부 확인 필요]\n$USER_LIST"

    output_checkpoint "$CODE" "$CAT" "$NAME" "$IMP" "$STD" "$RES" "$DESC" "$DT"
}

check07() {
    local CODE="D-07"
    local CAT="계정관리"
    local NAME="root 권한으로 서비스 구동 제한"
    local IMP="중"
    local STD="DBMS가 root 계정 또는 root 권한이 아닌 별도의 계정 및 권한으로 구동되고 있는 경우"
    local RES=""
    local DESC=""
    local DT=""

    local ORA_PROC=$(ps -ef | grep pmon | grep -v grep | head -1)
    local PROC_USER=$(echo "$ORA_PROC" | awk '{print $1}')

    local LSNR_PROC=$(ps -ef | grep tnslsnr | grep -v grep | head -1)
    local LSNR_USER=$(echo "$LSNR_PROC" | awk '{print $1}')

    DT="[Oracle PMON 프로세스]\n$ORA_PROC\n\n[Listener 프로세스]\n$LSNR_PROC"

    if [ -z "$ORA_PROC" ]; then
        RES="N/A"
        DESC="Oracle 프로세스를 찾을 수 없음"
    elif [ "$PROC_USER" == "root" ] || [ "$LSNR_USER" == "root" ]; then
        RES="N"
        DESC="Oracle 또는 Listener가 root 권한으로 구동 중"
    else
        RES="Y"
        DESC="Oracle이 일반 계정($PROC_USER)으로 구동 중"
    fi

    output_checkpoint "$CODE" "$CAT" "$NAME" "$IMP" "$STD" "$RES" "$DESC" "$DT"
}

check08() {
    local CODE="D-08"
    local CAT="계정관리"
    local NAME="안전한 암호화 알고리즘 사용"
    local IMP="상"
    local STD="해시 알고리즘 SHA-256 이상의 암호화 알고리즘을 사용하고 있는 경우"
    local RES=""
    local DESC=""
    local DT=""

        local PW_VERSIONS=$(echo "
    SET LINESIZE 200
    SELECT username, password_versions FROM dba_users WHERE username NOT LIKE '%\$%';
    " | $SQLPLUS_CMD 2>/dev/null)

        local SQLNET_FILE="$ORACLE_HOME/network/admin/sqlnet.ora"
        local SQLNET_CONTENT=""
        if [ -f "$SQLNET_FILE" ]; then
            SQLNET_CONTENT=$(grep -i "SQLNET.ALLOWED_LOGON_VERSION" "$SQLNET_FILE" 2>/dev/null)
        fi

        DT="[계정별 비밀번호 버전]\n$PW_VERSIONS\n\n[sqlnet.ora 설정]\n$SQLNET_CONTENT"

        # 취약한 암호화 알고리즘 사용 계정 체크 (10G만 있거나, 12C가 없는 경우)
        # - 10G만 있는 경우: 매우 취약
        # - 10G 11G만 있는 경우: 취약 (12C 없음)
        # - 11G만 있는 경우: 12C 해시 없으므로 취약
        # - 12C가 포함된 경우: 양호 (11G 12C, 10G 11G 12C 등)
        local WEAK_PW=$(echo "
    SELECT username FROM dba_users
    WHERE username NOT LIKE '%\$%'
    AND account_status = 'OPEN'
    AND (
        password_versions = '10G'
        OR password_versions = '10G 11G'
        OR password_versions = '11G'
        OR password_versions NOT LIKE '%12C%'
    );
    " | $SQLPLUS_CMD 2>/dev/null | grep -v "^USERNAME" | grep -v "^-" | grep -v "^$" | grep -v "no rows")

        # 10G 해시만 사용하는 매우 취약한 계정 별도 체크
        local VERY_WEAK=$(echo "
    SELECT username FROM dba_users
    WHERE username NOT LIKE '%\$%'
    AND account_status = 'OPEN'
    AND password_versions = '10G';
    " | $SQLPLUS_CMD 2>/dev/null | grep -v "^USERNAME" | grep -v "^-" | grep -v "^$" | grep -v "no rows")

        if [ -z "$WEAK_PW" ]; then
            RES="Y"
            DESC="안전한 암호화 알고리즘(12C) 사용 중"
        elif [ -n "$VERY_WEAK" ]; then
            RES="N"
            DESC="매우 취약한 암호화 알고리즘(10G only) 사용 계정 존재"
            DT="[매우 취약 계정 (10G only)]\n$VERY_WEAK\n\n[12C 미사용 계정]\n$WEAK_PW\n\n$DT"
        else
            RES="N"
            DESC="취약한 암호화 알고리즘 사용 (12C 해시 없음)"
            DT="[12C 미사용 계정]\n$WEAK_PW\n\n$DT"
        fi

    output_checkpoint "$CODE" "$CAT" "$NAME" "$IMP" "$STD" "$RES" "$DESC" "$DT"
}

check09() {
    local CODE="D-09"
    local CAT="계정관리"
    local NAME="일정 횟수의 로그인 실패 시 이에 대한 잠금정책 설정"
    local IMP="중"
    local STD="로그인 시도 횟수를 제한하는 값을 설정한 경우"
    local RES=""
    local DESC=""
    local DT=""

        local LOGIN_POLICY=$(echo "
    SET LINESIZE 200
    SELECT profile, resource_name, limit FROM dba_profiles
    WHERE resource_name = 'FAILED_LOGIN_ATTEMPTS';
    " | $SQLPLUS_CMD 2>/dev/null)

        DT="[로그인 실패 잠금 정책]\n$LOGIN_POLICY"

        local LOGIN_SET_RAW=$(echo "
    SET HEADING OFF
    SET FEEDBACK OFF
    SET PAGESIZE 0
    SELECT COUNT(*) FROM dba_profiles
    WHERE resource_name = 'FAILED_LOGIN_ATTEMPTS'
    AND limit != 'UNLIMITED';
    " | $SQLPLUS_CMD 2>/dev/null)
        # 숫자만 추출 (공백, 줄바꿈 제거)
        local LOGIN_SET=$(echo "$LOGIN_SET_RAW" | tr -d '[:space:]' | grep -oE '^[0-9]+' | head -1)
        LOGIN_SET=${LOGIN_SET:-0}

        if [ "$LOGIN_SET" -gt 0 ] 2>/dev/null; then
            RES="Y"
            DESC="로그인 실패 잠금 정책이 설정됨"
        else
            RES="N"
            DESC="로그인 실패 잠금 정책이 설정되지 않음"
        fi

    output_checkpoint "$CODE" "$CAT" "$NAME" "$IMP" "$STD" "$RES" "$DESC" "$DT"
}

check10() {
    local CODE="D-10"
    local CAT="접근관리"
    local NAME="원격에서 DB 서버로의 접속 제한"
    local IMP="상"
    local STD="DB 서버에 지정된 IP주소에서만 접근 가능하도록 제한한 경우"
    local RES=""
    local DESC=""
    local DT=""

    local RES="M"
    local DESC="listener.ora 및 sqlnet.ora 설정 수동 확인 필요"

    local LISTENER_FILE="$ORACLE_HOME/network/admin/listener.ora"
    local LISTENER_CONTENT=""
    if [ -f "$LISTENER_FILE" ]; then
        LISTENER_CONTENT=$(cat "$LISTENER_FILE" 2>/dev/null)
    else
        LISTENER_CONTENT="파일 없음"
    fi

    local SQLNET_FILE="$ORACLE_HOME/network/admin/sqlnet.ora"
    local VALIDNODE=""
    if [ -f "$SQLNET_FILE" ]; then
        VALIDNODE=$(grep -i "TCP.VALIDNODE" "$SQLNET_FILE" 2>/dev/null)
    fi

    DT="[listener.ora]\n$LISTENER_CONTENT\n\n[sqlnet.ora - TCP.VALIDNODE 설정]\n$VALIDNODE"

    output_checkpoint "$CODE" "$CAT" "$NAME" "$IMP" "$STD" "$RES" "$DESC" "$DT"
}

check11() {
    local CODE="D-11"
    local CAT="접근관리"
    local NAME="DBA 이외의 인가되지 않은 사용자가 시스템 테이블에 접근할 수 없도록 설정"
    local IMP="상"
    local STD="시스템 테이블에 DBA만 접근 가능하도록 설정되어 있는 경우"
    local RES=""
    local DESC=""
    local DT=""

        local SYS_TABLE_ACCESS=$(echo "
    SET LINESIZE 200
    SET PAGESIZE 100
    SELECT grantee, privilege, owner, table_name FROM dba_tab_privs
    WHERE (owner = 'SYS' OR table_name LIKE 'DBA_%')
    AND privilege <> 'EXECUTE'
    AND grantee NOT IN ('PUBLIC', 'DBA', 'SYS', 'SYSTEM', 'SELECT_CATALOG_ROLE',
    'EXECUTE_CATALOG_ROLE', 'DELETE_CATALOG_ROLE', 'EXP_FULL_DATABASE', 'IMP_FULL_DATABASE')
    AND grantee NOT IN (SELECT grantee FROM dba_role_privs WHERE granted_role = 'DBA');
    " | $SQLPLUS_CMD 2>/dev/null)

        DT="[시스템 테이블 접근 권한 (비인가 계정)]\n$SYS_TABLE_ACCESS"

        local ACCESS_COUNT=$(echo "$SYS_TABLE_ACCESS" | grep -v "^GRANTEE" | grep -v "^-" | grep -v "^$" | grep -v "no rows" | wc -l)

        if [ "$ACCESS_COUNT" -eq 0 ]; then
            RES="Y"
            DESC="시스템 테이블에 DBA만 접근 가능"
        else
            RES="N"
            DESC="일반 사용자에게 시스템 테이블 접근 권한 존재"
        fi

    output_checkpoint "$CODE" "$CAT" "$NAME" "$IMP" "$STD" "$RES" "$DESC" "$DT"
}

check12() {
    local CODE="D-12"
    local CAT="접근관리"
    local NAME="안전한 리스너 비밀번호 설정 및 사용"
    local IMP="상"
    local STD="Listener의 비밀번호가 설정된 경우"
    local RES=""
    local DESC=""
    local DT=""

    # 버전 파싱 (예: 12.2.0.1.0 -> 주버전=12, 부버전=2)
    local VERSION_MAJOR=$(echo "$ORACLE_VERSION" | cut -d'.' -f1)
    local VERSION_MINOR=$(echo "$ORACLE_VERSION" | cut -d'.' -f2)
    VERSION_MAJOR=${VERSION_MAJOR:-0}
    VERSION_MINOR=${VERSION_MINOR:-0}

    local LISTENER_FILE="$ORACLE_HOME/network/admin/listener.ora"
    local PW_SETTING=""
    local ADMIN_RESTRICT=""

    if [ -f "$LISTENER_FILE" ]; then
        PW_SETTING=$(grep -i "PASSWORDS_" "$LISTENER_FILE" 2>/dev/null)
        ADMIN_RESTRICT=$(grep -i "ADMIN_RESTRICTIONS" "$LISTENER_FILE" 2>/dev/null)
    fi

    DT="[Oracle Version]\n$ORACLE_VERSION\n\n[listener.ora 비밀번호 설정]\n$PW_SETTING\n\n[ADMIN_RESTRICTIONS 설정]\n$ADMIN_RESTRICT"

    # 12.2 이상 버전 체크 (12c R2 = 12.2.x)
    local IS_12_2_OR_HIGHER=0
    if [ "$VERSION_MAJOR" -gt 12 ] 2>/dev/null; then
        IS_12_2_OR_HIGHER=1
    elif [ "$VERSION_MAJOR" -eq 12 ] && [ "$VERSION_MINOR" -ge 2 ] 2>/dev/null; then
        IS_12_2_OR_HIGHER=1
    fi

    if [ "$IS_12_2_OR_HIGHER" -eq 1 ]; then
        # 12c R2(12.2) 이상에서는 리스너 비밀번호 미지원
        # ADMIN_RESTRICTIONS_<listener_name>=ON 설정만 확인
        if echo "$ADMIN_RESTRICT" | grep -qi "ON"; then
            RES="Y"
            DESC="ADMIN_RESTRICTIONS가 ON으로 설정됨 (12.2+ 권장 설정)"
        else
            RES="N/A"
            DESC="12.2 이상 버전에서는 리스너 비밀번호 미지원 (ADMIN_RESTRICTIONS 권장)"
            DT="$DT\n\n[참고]\n12c R2(12.2) 이상에서는 리스너 비밀번호가 더 이상 지원되지 않습니다.\nADMIN_RESTRICTIONS_<listener_name>=ON 설정을 권장합니다."
        fi
    elif [ "$VERSION_MAJOR" -ge 12 ] 2>/dev/null; then
        # 12c R1 (12.1.x)
        if echo "$ADMIN_RESTRICT" | grep -qi "ON"; then
            RES="Y"
            DESC="ADMIN_RESTRICTIONS가 ON으로 설정됨 (12c 권장 설정)"
        else
            RES="N"
            DESC="ADMIN_RESTRICTIONS가 설정되지 않음"
        fi
    else
        # 11g 이하
        if [ -n "$PW_SETTING" ]; then
            RES="Y"
            DESC="리스너 비밀번호가 설정됨"
        else
            RES="N"
            DESC="리스너 비밀번호가 설정되지 않음"
        fi
    fi

    output_checkpoint "$CODE" "$CAT" "$NAME" "$IMP" "$STD" "$RES" "$DESC" "$DT"
}

check13() {
    local CODE="D-13"
    local CAT="접근관리"
    local NAME="불필요한 ODBC/OLE-DB 데이터 소스와 드라이브를 제거하여 사용"
    local IMP="중"
    local STD="불필요한 ODBC/OLE-DB가 설치되지 않은 경우"
    local RES=""
    local DESC=""
    local DT=""

    local RES="N/A"
    local DESC="Windows MSSQL 점검 항목으로 Oracle Linux 환경에서는 해당 없음"
    DT="Oracle Linux 환경 — 해당 없음"

    output_checkpoint "$CODE" "$CAT" "$NAME" "$IMP" "$STD" "$RES" "$DESC" "$DT"
}

check14() {
    local CODE="D-14"
    local CAT="접근관리"
    local NAME="데이터베이스의 주요 설정 파일, 비밀번호 파일 등과 같은 주요 파일들의 접근 권한이 적절하게 설정"
    local IMP="중"
    local STD="주요 설정 파일 및 디렉터리의 권한 설정 시 일반 사용자의 수정 권한을 제거한 경우"
    local RES=""
    local DESC=""
    local DT=""

    local CHECKED_FILES=""
    local VULNERABLE_FILES=""

    # 파일 권한 체크 함수
    # SUID/SGID/Sticky 비트(4000, 2000, 1000)를 제외하고 기본 권한만 비교
    # 예: 6751 -> 751, 4755 -> 755
    check_file_perm() {
        local file="$1"
        local max_perm="$2"
        if [ -f "$file" ] || [ -d "$file" ]; then
            local full_perm=$(stat -c "%a" "$file" 2>/dev/null)
            local owner=$(stat -c "%U:%G" "$file" 2>/dev/null)

            # 기본 권한만 추출 (마지막 3자리)
            # 예: 6751 -> 751, 4755 -> 755, 755 -> 755
            local base_perm
            if [ ${#full_perm} -gt 3 ]; then
                base_perm=${full_perm: -3}
            else
                base_perm=$full_perm
            fi

            CHECKED_FILES="${CHECKED_FILES}${file}: ${full_perm} (${owner})\n"

            # 기본 권한이 최대 허용치보다 큰 경우에만 취약
            if [ "$base_perm" -gt "$max_perm" ] 2>/dev/null; then
                VULNERABLE_FILES="${VULNERABLE_FILES}${file}: ${full_perm} (기본권한: ${base_perm}, 권장: ${max_perm} 이하)\n"
            fi
        fi
    }

    for f in $ORACLE_HOME/dbs/init*.ora; do
        [ -f "$f" ] && check_file_perm "$f" 640
    done

    for f in $ORACLE_HOME/dbs/orapw*; do
        [ -f "$f" ] && check_file_perm "$f" 640
    done

    check_file_perm "$ORACLE_HOME/network/admin/listener.ora" 755
    check_file_perm "$ORACLE_HOME/network/admin/sqlnet.ora" 755
    check_file_perm "$ORACLE_HOME/network/admin/tnsnames.ora" 644
    check_file_perm "$ORACLE_HOME/network" 755
    check_file_perm "$ORACLE_HOME/lib" 755

    for bin in oracle sqlplus sqlldr exp imp tkprof tnsping wrap; do
        check_file_perm "$ORACLE_HOME/bin/$bin" 755
    done

    for bin in lsnrctl dbsnmp; do
        check_file_perm "$ORACLE_HOME/bin/$bin" 750
    done

    if [ -z "$CHECKED_FILES" ]; then
        RES="N/A"
        DESC="점검 대상 파일을 찾을 수 없음"
        DT="[확인된 파일 없음]\nORACLE_HOME: $ORACLE_HOME"
    elif [ -z "$VULNERABLE_FILES" ]; then
        RES="Y"
        DESC="주요 설정 파일의 권한이 적절하게 설정됨"
        DT="[파일 권한 현황]\n$CHECKED_FILES"
    else
        RES="N"
        DESC="주요 설정 파일의 권한이 과도하게 부여됨"
        DT="[취약 파일]\n$VULNERABLE_FILES\n[전체 파일]\n$CHECKED_FILES"
    fi

    output_checkpoint "$CODE" "$CAT" "$NAME" "$IMP" "$STD" "$RES" "$DESC" "$DT"
}

check15() {
    local CODE="D-15"
    local CAT="접근관리"
    local NAME="관리자 이외의 사용자가 오라클 리스너의 접속을 통해 리스너 로그 및 trace 파일에 대한 변경 제한"
    local IMP="하"
    local STD="Listener 관련 설정 파일에 대한 권한이 관리자로 설정되어 있으며, Listener로 파라미터를 변경할 수 없게 옵션이 설정된 경우"
    local RES=""
    local DESC=""
    local DT=""

    local LISTENER_FILE=""
    local LISTENER_PATH_SOURCE=""

    # 1. TNS_ADMIN 환경변수 우선 확인
    if [ -n "$TNS_ADMIN" ] && [ -f "$TNS_ADMIN/listener.ora" ]; then
        LISTENER_FILE="$TNS_ADMIN/listener.ora"
        LISTENER_PATH_SOURCE="TNS_ADMIN 환경변수"
    # 2. lsnrctl status에서 실제 경로 파싱 시도
    elif command -v lsnrctl &>/dev/null; then
        # lsnrctl status 출력에서 Listener Parameter File 경로 추출
        local LSNR_STATUS=$($ORACLE_HOME/bin/lsnrctl status 2>/dev/null || lsnrctl status 2>/dev/null)
        local LSNR_PARAM_FILE=$(echo "$LSNR_STATUS" | grep -i "Listener Parameter File" | sed 's/.*Listener Parameter File[[:space:]]*//;s/[[:space:]]*$//')
        if [ -n "$LSNR_PARAM_FILE" ] && [ -f "$LSNR_PARAM_FILE" ]; then
            LISTENER_FILE="$LSNR_PARAM_FILE"
            LISTENER_PATH_SOURCE="lsnrctl status"
        fi
    fi

    # 3. 기본 경로 fallback
    if [ -z "$LISTENER_FILE" ] && [ -f "$ORACLE_HOME/network/admin/listener.ora" ]; then
        LISTENER_FILE="$ORACLE_HOME/network/admin/listener.ora"
        LISTENER_PATH_SOURCE="ORACLE_HOME 기본 경로"
    fi

    local ADMIN_RESTRICT=""

    if [ -n "$LISTENER_FILE" ] && [ -f "$LISTENER_FILE" ]; then
        ADMIN_RESTRICT=$(grep -i "ADMIN_RESTRICTIONS" "$LISTENER_FILE" 2>/dev/null)
        local FILE_PERM=$(ls -la "$LISTENER_FILE" 2>/dev/null)
        DT="[listener.ora 경로]\n$LISTENER_FILE (출처: $LISTENER_PATH_SOURCE)\n\n[listener.ora 파일 권한]\n$FILE_PERM\n\n[ADMIN_RESTRICTIONS 설정]\n$ADMIN_RESTRICT"
    else
        DT="[listener.ora 파일을 찾을 수 없음]\n검색 경로:\n- TNS_ADMIN: ${TNS_ADMIN:-미설정}\n- ORACLE_HOME/network/admin: $ORACLE_HOME/network/admin"
        RES="N/A"
        DESC="listener.ora 파일을 찾을 수 없음"
        return
    fi

    if echo "$ADMIN_RESTRICT" | grep -qi "ON"; then
        RES="Y"
        DESC="ADMIN_RESTRICTIONS가 ON으로 설정됨"
    else
        RES="N"
        DESC="ADMIN_RESTRICTIONS가 설정되지 않음"
    fi

    output_checkpoint "$CODE" "$CAT" "$NAME" "$IMP" "$STD" "$RES" "$DESC" "$DT"
}

check16() {
    local CODE="D-16"
    local CAT="접근관리"
    local NAME="Windows 인증 모드 사용"
    local IMP="하"
    local STD="Windows 인증 모드를 사용하고 sa 계정이 비활성화되어 있는 경우 sa 계정 활성화 시 강력한 암호 정책을 설정한 경우"
    local RES=""
    local DESC=""
    local DT=""

    local RES="N/A"
    local DESC="Oracle은 Windows 인증 모드가 없음 (MSSQL 전용)"
    local DT="[참고]\nWindows 인증 모드는 Microsoft SQL Server 전용 기능입니다.\nOracle은 자체 인증 메커니즘(비밀번호 인증, OS 인증, Kerberos 등)을 사용합니다.\n\nOracle의 OS 인증은 OS_AUTHENT_PREFIX 파라미터와 REMOTE_OS_AUTHENT 파라미터로 제어됩니다.\n이 점검 항목은 MSSQL에만 해당됩니다."

    output_checkpoint "$CODE" "$CAT" "$NAME" "$IMP" "$STD" "$RES" "$DESC" "$DT"
}

check17() {
    local CODE="D-17"
    local CAT="옵션관리"
    local NAME="Audit Table은 데이터베이스 관리자 계정으로 접근하도록 제한"
    local IMP="하"
    local STD="Audit Table 접근 권한이 관리자 계정으로 설정한 경우"
    local RES=""
    local DESC=""
    local DT=""

        local AUD_OWNER=$(echo "
    SELECT owner FROM dba_tables WHERE table_name = 'AUD\$';
    " | $SQLPLUS_CMD 2>/dev/null | grep -v "^OWNER" | grep -v "^-" | grep -v "^$" | head -1)

        local AUD_PRIVS=$(echo "
    SET LINESIZE 200
    SELECT grantee, privilege FROM dba_tab_privs WHERE table_name = 'AUD\$';
    " | $SQLPLUS_CMD 2>/dev/null)

        DT="[AUD\$ 테이블 소유자]\n$AUD_OWNER\n\n[AUD\$ 테이블 접근 권한]\n$AUD_PRIVS"

        if [ "$AUD_OWNER" == "SYS" ]; then
            RES="Y"
            DESC="Audit Table이 SYS 소유로 설정됨"
        else
            RES="N"
            DESC="Audit Table 소유자가 SYS가 아님"
        fi

    output_checkpoint "$CODE" "$CAT" "$NAME" "$IMP" "$STD" "$RES" "$DESC" "$DT"
}

check18() {
    local CODE="D-18"
    local CAT="옵션관리"
    local NAME="응용프로그램 또는 DBA 계정의 Role이 Public으로 설정되지 않도록 조정"
    local IMP="상"
    local STD="DBA 계정의 Role이 Public으로 설정되지 않은 경우"
    local RES=""
    local DESC=""
    local DT=""

        local PUBLIC_ROLES=$(echo "
    SET LINESIZE 200
    SELECT granted_role FROM dba_role_privs WHERE grantee = 'PUBLIC';
    " | $SQLPLUS_CMD 2>/dev/null)

        local PUBLIC_PRIVS=$(echo "
    SELECT privilege FROM dba_sys_privs WHERE grantee = 'PUBLIC';
    " | $SQLPLUS_CMD 2>/dev/null)

        DT="[PUBLIC에 부여된 Role]\n$PUBLIC_ROLES\n\n[PUBLIC에 부여된 시스템 권한]\n$PUBLIC_PRIVS"

        local DANGER_PRIVS_RAW=$(echo "
    SET HEADING OFF
    SET FEEDBACK OFF
    SET PAGESIZE 0
    SELECT COUNT(*) FROM dba_sys_privs
    WHERE grantee = 'PUBLIC'
    AND privilege IN ('CREATE SESSION', 'CREATE TABLE', 'CREATE VIEW', 'CREATE PROCEDURE',
    'ALTER SYSTEM', 'DROP ANY TABLE', 'DELETE ANY TABLE');
    " | $SQLPLUS_CMD 2>/dev/null)
        # 숫자만 추출 (공백, 줄바꿈 제거)
        local DANGER_PRIVS=$(echo "$DANGER_PRIVS_RAW" | tr -d '[:space:]' | grep -oE '^[0-9]+' | head -1)
        DANGER_PRIVS=${DANGER_PRIVS:-0}

        if [ "$DANGER_PRIVS" -eq 0 ] 2>/dev/null; then
            RES="Y"
            DESC="PUBLIC에 위험한 권한이 부여되지 않음"
        else
            RES="N"
            DESC="PUBLIC에 위험한 권한이 부여됨"
        fi

    output_checkpoint "$CODE" "$CAT" "$NAME" "$IMP" "$STD" "$RES" "$DESC" "$DT"
}

check19() {
    local CODE="D-19"
    local CAT="옵션관리"
    local NAME="OS_ROLES, REMOTE_OS_AUTHENTICATION, REMOTE_OS_ROLES를 FALSE로 설정"
    local IMP="상"
    local STD="OS_ROLES, REMOTE_OS_AUTHENTICATION, REMOTE_OS_ROLES 설정이 FALSE로 설정된 경우"
    local RES=""
    local DESC=""
    local DT=""

        local OS_PARAMS=$(echo "
    SET LINESIZE 200
    SELECT name, value FROM v\$parameter
    WHERE name IN ('os_roles', 'remote_os_authent', 'remote_os_roles');
    " | $SQLPLUS_CMD 2>/dev/null)

        DT="[OS 관련 파라미터]\n$OS_PARAMS"

        local TRUE_COUNT_RAW=$(echo "
    SET HEADING OFF
    SET FEEDBACK OFF
    SET PAGESIZE 0
    SELECT COUNT(*) FROM v\$parameter
    WHERE name IN ('os_roles', 'remote_os_authent', 'remote_os_roles')
    AND UPPER(value) = 'TRUE';
    " | $SQLPLUS_CMD 2>/dev/null)
        # 숫자만 추출 (공백, 줄바꿈 제거)
        local TRUE_COUNT=$(echo "$TRUE_COUNT_RAW" | tr -d '[:space:]' | grep -oE '^[0-9]+' | head -1)
        TRUE_COUNT=${TRUE_COUNT:-0}

        if [ "$TRUE_COUNT" -eq 0 ] 2>/dev/null; then
            RES="Y"
            DESC="OS_ROLES, REMOTE_OS_AUTHENT, REMOTE_OS_ROLES가 모두 FALSE"
        else
            RES="N"
            DESC="OS 관련 파라미터 중 TRUE로 설정된 항목 존재"
        fi

    output_checkpoint "$CODE" "$CAT" "$NAME" "$IMP" "$STD" "$RES" "$DESC" "$DT"
}

check20() {
    local CODE="D-20"
    local CAT="옵션관리"
    local NAME="인가되지 않은 Object Owner의 제한"
    local IMP="하"
    local STD="Object Owner가 SYS, SYSTEM, 관리자 계정 등으로 제한된 경우"
    local RES=""
    local DESC=""
    local DT=""

        local RES="M"
        local DESC="Object Owner 목록 수동 확인 필요"

        local OBJECT_OWNERS=$(echo "
    SET LINESIZE 200
    SELECT DISTINCT owner FROM dba_objects
    WHERE owner NOT IN ('SYS', 'SYSTEM', 'MDSYS', 'CTXSYS', 'ORDSYS', 'ORDPLUGINS',
    'AURORA\$JIS\$UTILITY\$', 'HR', 'ODM', 'ODM_MTR', 'OE', 'OLAPSYS', 'OUTLN',
    'LBACSYS', 'PUBLIC', 'DBSNMP', 'RMAN', 'WKSYS', 'WMSYS', 'XDB', 'EXFSYS',
    'SYSMAN', 'ORDDATA', 'APEX_040000', 'APEX_030200', 'FLOWS_FILES')
    AND owner NOT IN (SELECT grantee FROM dba_role_privs WHERE granted_role = 'DBA')
    ORDER BY owner;
    " | $SQLPLUS_CMD 2>/dev/null)

        DT="[비표준 Object Owner 목록 - 확인 필요]\n$OBJECT_OWNERS"

    output_checkpoint "$CODE" "$CAT" "$NAME" "$IMP" "$STD" "$RES" "$DESC" "$DT"
}

check21() {
    local CODE="D-21"
    local CAT="옵션관리"
    local NAME="인가되지 않은 GRANT OPTION 사용 제한"
    local IMP="중"
    local STD="WITH_GRANT_OPTION이 ROLE에 의하여 설정된 경우"
    local RES=""
    local DESC=""
    local DT=""

        local GRANT_OPTION=$(echo "
    SET LINESIZE 200
    SELECT grantee || ':' || owner || '.' || table_name AS grant_info
    FROM dba_tab_privs
    WHERE grantable = 'YES'
    AND owner NOT IN ('SYS', 'MDSYS', 'ORDPLUGINS', 'ORDSYS', 'SYSTEM', 'WMSYS', 'LBACSYS')
    AND grantee NOT IN (SELECT grantee FROM dba_role_privs WHERE granted_role = 'DBA')
    ORDER BY grantee;
    " | $SQLPLUS_CMD 2>/dev/null)

        DT="[WITH GRANT OPTION 보유 계정]\n$GRANT_OPTION"

        local GRANT_COUNT=$(echo "$GRANT_OPTION" | grep -v "^GRANT_INFO" | grep -v "^-" | grep -v "^$" | grep -v "no rows" | wc -l)

        if [ "$GRANT_COUNT" -eq 0 ]; then
            RES="Y"
            DESC="비인가 계정에 GRANT OPTION이 부여되지 않음"
        else
            RES="N"
            DESC="비인가 계정에 GRANT OPTION이 부여됨"
        fi

    output_checkpoint "$CODE" "$CAT" "$NAME" "$IMP" "$STD" "$RES" "$DESC" "$DT"
}

check22() {
    local CODE="D-22"
    local CAT="옵션관리"
    local NAME="데이터베이스의 자원 제한 기능을 TRUE로 설정"
    local IMP="하"
    local STD="RESOURCE_LIMIT 설정이 TRUE로 되어있는 경우"
    local RES=""
    local DESC=""
    local DT=""

        local RESOURCE_LIMIT=$(echo "
    SELECT value FROM v\$parameter WHERE name = 'resource_limit';
    " | $SQLPLUS_CMD 2>/dev/null | grep -v "^VALUE" | grep -v "^-" | grep -v "^$" | head -1)

        DT="[RESOURCE_LIMIT 설정]\n$RESOURCE_LIMIT"

        if [ "$RESOURCE_LIMIT" == "TRUE" ]; then
            RES="Y"
            DESC="RESOURCE_LIMIT이 TRUE로 설정됨"
        else
            RES="N"
            DESC="RESOURCE_LIMIT이 FALSE로 설정됨"
        fi

    output_checkpoint "$CODE" "$CAT" "$NAME" "$IMP" "$STD" "$RES" "$DESC" "$DT"
}

check23() {
    local CODE="D-23"
    local CAT="옵션관리"
    local NAME="xp_cmdshell 사용 제한"
    local IMP="상"
    local STD="xp_cmdshell이 비활성화 되어 있거나, 활성화 되어 있으면 다음의 조건을 모두 만족하는 경우 1. public의 실행(Execute) 권한이 부여되어 있지 않은 경우 2. 서비스 계정(애플리케이션 연동)에 sysadmin 권한이 부여되어 있지 않은 경우"
    local RES=""
    local DESC=""
    local DT=""

    local RES="N/A"
    local DESC="Oracle은 xp_cmdshell이 없음 (MSSQL 전용)"
    local DT="[참고]\nxp_cmdshell은 Microsoft SQL Server에서 운영체제 명령을 실행하는 확장 저장 프로시저입니다.\nOracle은 xp_cmdshell 기능을 지원하지 않습니다.\n\nOracle에서 OS 명령 실행이 필요한 경우 DBMS_SCHEDULER나 외부 프로시저(extproc)를 사용합니다.\n이 점검 항목은 MSSQL에만 해당됩니다."

    output_checkpoint "$CODE" "$CAT" "$NAME" "$IMP" "$STD" "$RES" "$DESC" "$DT"
}

check24() {
    local CODE="D-24"
    local CAT="옵션관리"
    local NAME="Registry Procedure 권한 제한"
    local IMP="상"
    local STD="제한이 필요한 시스템 확장 저장 프로시저들이 DBA 외 guest/public에게 부여되지 않은 경우"
    local RES=""
    local DESC=""
    local DT=""

    local RES="N/A"
    local DESC="Oracle은 Registry Procedure가 없음 (MSSQL 전용)"
    local DT="[참고]\nRegistry Stored Procedure(xp_regread, xp_regwrite 등)는 Microsoft SQL Server에서\nWindows 레지스트리를 읽고 쓰는 확장 저장 프로시저입니다.\n\nOracle은 Windows 레지스트리 접근 기능을 제공하지 않습니다.\n이 점검 항목은 MSSQL에만 해당됩니다."

    output_checkpoint "$CODE" "$CAT" "$NAME" "$IMP" "$STD" "$RES" "$DESC" "$DT"
}

check25() {
    local CODE="D-25"
    local CAT="패치관리"
    local NAME="주기적 보안 패치 및 벤더 권고 사항 적용"
    local IMP="상"
    local STD="보안 패치가 적용된 버전을 사용하는 경우"
    local RES=""
    local DESC=""
    local DT=""

        local RES="M"
        local DESC="현재 버전 확인 후 최신 패치 적용 여부 수동 확인 필요"

        local PATCH_INFO=$(echo "
    SET LINESIZE 200
    SELECT * FROM dba_registry_sqlpatch ORDER BY install_id DESC;
    " | $SQLPLUS_CMD 2>/dev/null)

        DT="[현재 버전]\n$DB_VERSION\n\n[설치된 패치]\n$PATCH_INFO\n\n※ 최신 버전은 Oracle 공식 사이트에서 확인\nhttps://www.oracle.com/security-alerts/"

    output_checkpoint "$CODE" "$CAT" "$NAME" "$IMP" "$STD" "$RES" "$DESC" "$DT"
}

check26() {
    local CODE="D-26"
    local CAT="패치관리"
    local NAME="데이터베이스의 접근, 변경, 삭제 등의 감사 기록이 기관의 감사 기록 정책에 적합하도록 설정"
    local IMP="상"
    local STD="DBMS의 감사 로그 저장 정책이 수립되어 있으며, 정책 설정이 적용된 경우"
    local RES=""
    local DESC=""
    local DT=""

        local AUDIT_TRAIL=$(echo "
    SELECT value FROM v\$parameter WHERE name = 'audit_trail';
    " | $SQLPLUS_CMD 2>/dev/null | grep -v "^VALUE" | grep -v "^-" | grep -v "^$" | head -1)

        local AUDIT_POLICY=$(echo "
    SET LINESIZE 200
    SELECT audit_option, success, failure FROM dba_stmt_audit_opts;
    " | $SQLPLUS_CMD 2>/dev/null)

        DT="[AUDIT_TRAIL 설정]\n$AUDIT_TRAIL\n\n[감사 정책]\n$AUDIT_POLICY"

        if [ "$AUDIT_TRAIL" == "NONE" ] || [ -z "$AUDIT_TRAIL" ]; then
            RES="N"
            DESC="감사 로그(AUDIT_TRAIL)가 비활성화됨"
        else
            RES="Y"
            DESC="감사 로그가 활성화됨 (AUDIT_TRAIL=$AUDIT_TRAIL)"
        fi

    output_checkpoint "$CODE" "$CAT" "$NAME" "$IMP" "$STD" "$RES" "$DESC" "$DT"
}


#================================================================
# EXECUTE
#================================================================

echo ""
echo "  $META_PLAT Security Assessment v$META_VER [$META_STD]"
echo "  ─────────────────────────────────────────────────────────"
echo ""
echo "  호스트: $SYS_HOST"
echo "  DBMS: $META_PLAT $DB_VERSION"
echo ""
echo "  [진단 시작]"
echo "  ─────────────────────────────────────────────────────────"
echo ""

# XML 헤더
cat > "$OUTPUT_FILE" << XMLEOF
<?xml version="1.0" encoding="UTF-8"?>
<seedgen>
    <meta>
        <date>$META_DATE</date>
        <ver>$META_VER</ver>
        <plat>$META_PLAT</plat>
        <type>$META_TYPE</type>
        <std>$META_STD</std>
    </meta>
    <sys>
        <host>$SYS_HOST</host>
        <dom>$SYS_DOM</dom>
        <os>
            <n>$META_PLAT $DB_VERSION</n>
            <fn>$META_PLAT</fn>
        </os>
        <kn>$DB_VERSION</kn>
        <arch>$(uname -m)</arch>
        <net>
            <ip>${DB_HOST:-localhost}</ip>
            <all><![CDATA[Host: ${DB_HOST:-localhost}, Port: ${DB_PORT:-N/A}]]></all>
        </net>
    </sys>
    <results>
XMLEOF

# 진단 실행
    check01
    check02
    check03
    check04
    check05
    check06
    check07
    check08
    check09
    check10
    check11
    check12
    check13
    check14
    check15
    check16
    check17
    check18
    check19
    check20
    check21
    check22
    check23
    check24
    check25
    check26

# XML 종료
cat >> "$OUTPUT_FILE" << XMLEOF
    </results>
</seedgen>
XMLEOF

#================================================================
# CLEANUP
#================================================================
echo ""
echo "  ─────────────────────────────────────────────────────────"
echo ""
echo "  점검이 완료되었습니다!"
echo "  호스트: $SYS_HOST"
echo "  결과 파일: $OUTPUT_FILE"
echo ""
