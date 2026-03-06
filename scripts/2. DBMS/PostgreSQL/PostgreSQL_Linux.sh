#!/bin/bash
#================================================================
# PostgreSQL_Linux 보안 진단 스크립트
# KISA 주요정보통신기반시설 기술적 취약점 분석·평가 기준
#================================================================
# 버전  : 2603070
# 대상  : PostgreSQL_Linux
# 항목  : D-01 ~ D-26 (26개)
# 제작  : Seedgen
#================================================================
META_STD="KISA"

#================================================================
# INIT
#================================================================
META_VER="1.0"
META_PLAT="PostgreSQL"
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
echo ""
echo "============================================================"
echo " PostgreSQL 보안 진단 스크립트"
echo "============================================================"
echo ""
echo "[연결 정보 입력]"
echo ""

# psql 클라이언트 확인
PSQL_CLIENT=$(which psql 2>/dev/null)
if [ -z "$PSQL_CLIENT" ]; then
    echo -n "psql Client Path (psql not found): "
    read PSQL_CLIENT
    if [ ! -x "$PSQL_CLIENT" ]; then
        echo "[!] psql 클라이언트를 찾을 수 없습니다."
        exit 1
    fi
fi

# 연결 정보 입력
echo -n "Host (default: localhost): "
read DB_HOST
DB_HOST=${DB_HOST:-localhost}

echo -n "Port (default: 5432): "
read DB_PORT
DB_PORT=${DB_PORT:-5432}

echo -n "Database (default: postgres): "
read DB_NAME
DB_NAME=${DB_NAME:-postgres}

echo -n "User (default: postgres): "
read DB_USER
DB_USER=${DB_USER:-postgres}

echo -n "Password: "
read -s DB_PASS
echo ""

if [ -z "$DB_PASS" ]; then
    echo "[!] 비밀번호를 입력해주세요."
    exit 1
fi

# PostgreSQL 연결 명령어
export PGPASSWORD="$DB_PASS"
PSQL_CMD="$PSQL_CLIENT -h $DB_HOST -p $DB_PORT -U $DB_USER -d $DB_NAME -t -A"

# 연결 테스트
echo ""
echo "[연결 테스트 중...]"
DB_VERSION=$($PSQL_CMD -c "SELECT version();" 2>/dev/null)
if [ $? -ne 0 ]; then
    echo "[!] PostgreSQL 연결 실패"
    exit 1
fi
echo "[OK] PostgreSQL 연결 성공"
echo "    $DB_VERSION"
echo ""

# PostgreSQL 버전 정보
PG_VERSION=$($PSQL_CMD -c "SHOW server_version;" 2>/dev/null)
PG_DATA_DIR=$($PSQL_CMD -c "SHOW data_directory;" 2>/dev/null)

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

    local RES="M"
    local DESC="postgres 계정 비밀번호 변경 여부 수동 확인 필요"

    local USER_LIST=$($PSQL_CMD -c "
        SELECT usename, usesuper, usecreatedb, userepl, passwd IS NOT NULL as has_password
        FROM pg_shadow ORDER BY usename;
    " 2>/dev/null)

    DT="[사용자 목록]\n$USER_LIST\n\n※ postgres 계정의 초기 비밀번호 변경 여부 확인 필요"

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

    local ROLE_LIST=$($PSQL_CMD -c "
        SELECT rolname, rolsuper, rolcreaterole, rolcreatedb, rolcanlogin, rolconnlimit
        FROM pg_roles ORDER BY rolname;
    " 2>/dev/null)

    DT="[역할(계정) 목록 - 불필요 계정 여부 확인 필요]\n$ROLE_LIST"

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

    local RES="M"
    local DESC="비밀번호 정책 수동 확인 필요 (PostgreSQL은 외부 인증 모듈 사용)"

    local PW_SETTINGS=$($PSQL_CMD -c "
        SELECT name, setting FROM pg_settings
        WHERE name IN ('password_encryption', 'scram_iterations');
    " 2>/dev/null)

    local PW_EXPIRY=$($PSQL_CMD -c "
        SELECT rolname, rolvaliduntil FROM pg_roles WHERE rolvaliduntil IS NOT NULL;
    " 2>/dev/null)

    DT="[비밀번호 설정]\n$PW_SETTINGS\n\n[비밀번호 만료 설정된 계정]\n$PW_EXPIRY\n\n※ PostgreSQL은 기본적으로 비밀번호 복잡도 검증 기능이 없음\n※ pgaudit, credcheck 확장 모듈 사용 권장"

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
    local DESC="SUPERUSER 권한 보유 계정 수동 확인 필요"

    local SUPER_USERS=$($PSQL_CMD -c "
        SELECT usename FROM pg_shadow WHERE usesuper = true;
    " 2>/dev/null)

    local ADMIN_ROLES=$($PSQL_CMD -c "
        SELECT rolname, rolsuper, rolcreaterole, rolcreatedb, rolreplication, rolbypassrls
        FROM pg_roles WHERE rolsuper = true OR rolcreaterole = true OR rolcreatedb = true
        ORDER BY rolname;
    " 2>/dev/null)

    DT="[SUPERUSER 권한 보유 계정]\n$SUPER_USERS\n\n[관리 권한 보유 계정]\n$ADMIN_ROLES"

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

    local RES="N/A"
    local DESC="PostgreSQL은 기본적으로 비밀번호 재사용 제한 기능을 제공하지 않음"

    DT="PostgreSQL은 비밀번호 히스토리 관리 기능을 기본 제공하지 않습니다.\n외부 인증 시스템(LDAP, AD 등) 또는 확장 모듈 사용을 권장합니다."

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

    local LOGIN_ROLES=$($PSQL_CMD -c "
        SELECT rolname, rolcanlogin FROM pg_roles
        WHERE rolcanlogin = true ORDER BY rolname;
    " 2>/dev/null)

    DT="[로그인 가능 계정 목록 - 개별 계정 사용 여부 확인 필요]\n$LOGIN_ROLES"

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

    local PG_PROC=$(ps -ef | grep postgres | grep -v grep | head -3)
    local PROC_USER=$(ps -ef | grep "postgres:" | grep -v grep | head -1 | awk '{print $1}')

    DT="[PostgreSQL 프로세스]\n$PG_PROC"

    if [ -z "$PG_PROC" ]; then
        RES="N/A"
        DESC="PostgreSQL 프로세스를 찾을 수 없음"
    elif [ "$PROC_USER" == "root" ]; then
        RES="N"
        DESC="PostgreSQL이 root 권한으로 구동 중"
    else
        RES="Y"
        DESC="PostgreSQL이 일반 계정($PROC_USER)으로 구동 중"
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

    local PW_ENCRYPTION=$($PSQL_CMD -c "SHOW password_encryption;" 2>/dev/null)

    local PW_FORMAT=$($PSQL_CMD -c "
        SELECT usename,
               CASE WHEN passwd LIKE 'SCRAM-SHA-256%' THEN 'SCRAM-SHA-256'
                    WHEN passwd LIKE 'md5%' THEN 'MD5'
                    ELSE 'OTHER' END as pw_type
        FROM pg_shadow WHERE passwd IS NOT NULL;
    " 2>/dev/null)

    DT="[비밀번호 암호화 설정]\npassword_encryption = $PW_ENCRYPTION\n\n[계정별 비밀번호 형식]\n$PW_FORMAT"

    if [ "$PW_ENCRYPTION" == "scram-sha-256" ]; then
        RES="Y"
        DESC="안전한 암호화 알고리즘(SCRAM-SHA-256) 사용 중"
    elif [ "$PW_ENCRYPTION" == "md5" ]; then
        RES="N"
        DESC="MD5 암호화 사용 중 (SCRAM-SHA-256 권장)"
    else
        RES="M"
        DESC="암호화 알고리즘 수동 확인 필요"
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

    local RES="N/A"
    local DESC="PostgreSQL은 기본적으로 로그인 실패 잠금 기능을 제공하지 않음"

    local CONN_LIMIT=$($PSQL_CMD -c "
        SELECT rolname, rolconnlimit FROM pg_roles WHERE rolconnlimit > 0;
    " 2>/dev/null)

    DT="[연결 제한 설정된 계정]\n$CONN_LIMIT\n\n※ PostgreSQL은 로그인 실패 잠금 기능을 기본 제공하지 않음\n※ pg_faillock 확장 또는 운영체제 수준의 제어 권장"

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

    local LISTEN_ADDR=$($PSQL_CMD -c "SHOW listen_addresses;" 2>/dev/null)
    local HBA_FILE=$($PSQL_CMD -c "SHOW hba_file;" 2>/dev/null)

    local HBA_CONTENT=""
    if [ -f "$HBA_FILE" ]; then
        HBA_CONTENT=$(grep -v "^#" "$HBA_FILE" | grep -v "^$" 2>/dev/null)
    fi

    DT="[listen_addresses]\n$LISTEN_ADDR\n\n[pg_hba.conf 위치]\n$HBA_FILE\n\n[pg_hba.conf 접근 제어 설정]\n$HBA_CONTENT"

    if [ "$LISTEN_ADDR" == "*" ]; then
        RES="N"
        DESC="모든 IP에서 접속 가능 (listen_addresses = *)"
    elif [ "$LISTEN_ADDR" == "localhost" ] || [ "$LISTEN_ADDR" == "127.0.0.1" ]; then
        RES="Y"
        DESC="로컬 접속만 허용됨"
    else
        RES="M"
        DESC="접근 제한 설정 수동 확인 필요"
    fi

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

    local RES="M"
    local DESC="시스템 카탈로그 접근 권한 수동 확인 필요"

    local PUBLIC_GRANTS=$($PSQL_CMD -c "
        SELECT nspname, privilege_type FROM information_schema.role_usage_grants
        WHERE grantee = 'PUBLIC' AND object_schema IN ('pg_catalog', 'information_schema')
        LIMIT 20;
    " 2>/dev/null)

    local CATALOG_PRIVS=$($PSQL_CMD -c "
        SELECT grantee, privilege_type FROM information_schema.role_table_grants
        WHERE table_schema = 'pg_catalog' AND grantee != 'postgres'
        LIMIT 20;
    " 2>/dev/null)

    DT="[PUBLIC 스키마 권한]\n$PUBLIC_GRANTS\n\n[pg_catalog 접근 권한]\n$CATALOG_PRIVS\n\n※ PostgreSQL은 기본적으로 시스템 카탈로그 읽기 권한이 PUBLIC에 부여됨"

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

    local RES="N/A"
    local DESC="N/A (PostgreSQL은 리스너 개념이 없음)"

    DT="해당 항목은 Oracle TNS Listener의 비밀번호 설정을 점검하는 항목입니다.\nPostgreSQL은 Oracle과 달리 별도의 리스너(Listener) 프로세스가 없으므로\n본 항목은 PostgreSQL 환경에서 점검 대상에서 제외됩니다."

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
    local DESC="N/A (PostgreSQL은 ODBC/OLE-DB 드라이버 관리가 OS 영역)"

    DT="[N/A 사유]\nPostgreSQL은 데이터베이스 서버이며, ODBC/OLE-DB 데이터 소스 및 드라이버 관리는 클라이언트 OS 영역입니다.\n서버 측에서 점검해야 할 ODBC/OLE-DB 설정이 없으므로, 해당 항목은 적용되지 않습니다.\n\n[참고]\n- ODBC 드라이버: 클라이언트 OS에서 관리 (Windows: ODBC 데이터 원본 관리자)\n- OLE-DB: Windows 클라이언트 전용 기술\n- PostgreSQL 서버는 클라이언트 연결을 수신하는 역할만 수행"

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

    # PostgreSQL 설정 파일 경로 조회
    local CONFIG_FILE=$($PSQL_CMD -t -c "SHOW config_file;" 2>/dev/null | tr -d '[:space:]')
    local HBA_FILE=$($PSQL_CMD -t -c "SHOW hba_file;" 2>/dev/null | tr -d '[:space:]')
    local IDENT_FILE=$($PSQL_CMD -t -c "SHOW ident_file;" 2>/dev/null | tr -d '[:space:]')
    local DATA_DIR=$($PSQL_CMD -t -c "SHOW data_directory;" 2>/dev/null | tr -d '[:space:]')
    local LOG_DIR=$($PSQL_CMD -t -c "SHOW log_directory;" 2>/dev/null | tr -d '[:space:]')

    # 파일 정보 수집 함수
    get_file_info() {
        local filepath="$1"
        if [ -e "$filepath" ]; then
            local perm=$(stat -c "%a" "$filepath" 2>/dev/null)
            local owner=$(stat -c "%U:%G" "$filepath" 2>/dev/null)
            echo "경로: $filepath"
            echo "권한: $perm"
            echo "소유자: $owner"
        else
            echo "경로: $filepath (파일 없음)"
        fi
    }

    DT="[postgresql.conf]\n"
    if [ -n "$CONFIG_FILE" ]; then
        DT="${DT}$(get_file_info "$CONFIG_FILE")"
    else
        DT="${DT}경로 확인 불가"
    fi

    DT="${DT}\n\n[pg_hba.conf]\n"
    if [ -n "$HBA_FILE" ]; then
        DT="${DT}$(get_file_info "$HBA_FILE")"
    else
        DT="${DT}경로 확인 불가"
    fi

    DT="${DT}\n\n[pg_ident.conf]\n"
    if [ -n "$IDENT_FILE" ]; then
        DT="${DT}$(get_file_info "$IDENT_FILE")"
    else
        DT="${DT}경로 확인 불가"
    fi

    DT="${DT}\n\n[data 디렉터리]\n"
    if [ -d "$DATA_DIR" ]; then
        DT="${DT}$(get_file_info "$DATA_DIR")"
    else
        DT="${DT}경로 확인 불가"
    fi

    # 로그 파일 권한 확인
    DT="${DT}\n\n[로그 디렉터리]\n"
    local FULL_LOG_DIR="$LOG_DIR"
    # 상대 경로인 경우 data_directory 기준으로 변환
    if [ -n "$LOG_DIR" ] && [[ ! "$LOG_DIR" = /* ]]; then
        FULL_LOG_DIR="${DATA_DIR}/${LOG_DIR}"
    fi
    if [ -d "$FULL_LOG_DIR" ]; then
        DT="${DT}$(get_file_info "$FULL_LOG_DIR")\n"
        # 최근 로그 파일 샘플 확인
        local LOG_FILES=$(ls -la "$FULL_LOG_DIR"/*.log 2>/dev/null | head -3)
        if [ -n "$LOG_FILES" ]; then
            DT="${DT}\n[로그 파일 샘플]\n$LOG_FILES"
        fi
    else
        DT="${DT}경로: $FULL_LOG_DIR (디렉터리 없음)"
    fi

    # 권한 검사
    local INSECURE=0
    for file in "$CONFIG_FILE" "$HBA_FILE"; do
        if [ -f "$file" ]; then
            local PERM=$(stat -c "%a" "$file" 2>/dev/null)
            if [ -n "$PERM" ]; then
                local OTHER_WRITE=$((PERM % 10))
                local GROUP_WRITE=$(((PERM / 10) % 10))
                if [ $((OTHER_WRITE & 2)) -ne 0 ] || [ $((GROUP_WRITE & 2)) -ne 0 ]; then
                    INSECURE=1
                fi
            fi
        fi
    done

    if [ $INSECURE -eq 0 ]; then
        RES="Y"
        DESC="주요 설정 파일 권한이 적절함"
    else
        RES="N"
        DESC="주요 설정 파일에 과도한 권한 존재"
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

    local RES="N/A"
    local DESC="N/A (PostgreSQL은 Oracle trace 파일이 없음)"

    DT="해당 항목은 Oracle Listener의 로그 및 trace 파일에 대한 접근 권한을 점검하는 항목입니다.\nPostgreSQL은 Oracle과 달리 별도의 리스너(Listener) 프로세스와 trace 파일이 없으므로\n본 항목은 PostgreSQL 환경에서 점검 대상에서 제외됩니다.\n\n※ PostgreSQL의 로그 파일 권한은 D-14 항목에서 점검합니다."

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
    local DESC="N/A (PostgreSQL은 Windows 인증 모드가 없음)"

    DT="해당 항목은 MSSQL의 Windows 통합 인증 사용 여부를 점검하는 항목입니다.\nPostgreSQL은 MSSQL의 Windows 인증 모드 개념이 없으므로\n본 항목은 PostgreSQL 환경에서 점검 대상에서 제외됩니다.\n\n※ PostgreSQL은 pg_hba.conf를 통해 인증 방식을 설정합니다.\n※ LDAP, GSSAPI, SSPI 등 다양한 인증 방식을 지원합니다."

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

    local RES="N/A"
    local DESC="N/A (PostgreSQL은 Oracle AUD$ 테이블이 없음)"

    DT="해당 항목은 Oracle의 AUD$ 감사 테이블에 대한 접근 권한을 점검하는 항목입니다.\nPostgreSQL은 Oracle과 같은 AUD$ 테이블이 없으므로\n본 항목은 PostgreSQL 환경에서 점검 대상에서 제외됩니다.\n\n※ PostgreSQL의 감사 기능은 pgaudit 확장 또는 log_statement 설정을 사용합니다."

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

    local RES="N/A"
    local DESC="N/A (PostgreSQL은 Oracle PUBLIC 롤 개념이 다름)"

    DT="해당 항목은 Oracle의 PUBLIC 롤에 부여된 권한을 점검하는 항목입니다.\nPostgreSQL은 public 스키마에 대한 기본 권한 관리 방식이 Oracle과 다르므로\n본 항목은 PostgreSQL 환경에서 점검 대상에서 제외됩니다.\n\n※ PostgreSQL의 public 스키마 권한은 D-11 항목에서 점검합니다.\n※ REVOKE ALL ON SCHEMA public FROM PUBLIC; 명령으로 제한 가능합니다."

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

    local RES="N/A"
    local DESC="N/A (PostgreSQL은 Oracle OS_ROLES 파라미터가 없음)"

    DT="해당 항목은 Oracle의 OS_ROLES, REMOTE_OS_AUTHENT, REMOTE_OS_ROLES 파라미터를\nFALSE로 설정했는지 점검하는 항목입니다.\nPostgreSQL은 이러한 파라미터가 없으므로\n본 항목은 PostgreSQL 환경에서 점검 대상에서 제외됩니다.\n\n※ PostgreSQL의 OS 인증은 pg_hba.conf의 peer/ident 방식으로 관리됩니다."

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

    local OBJECT_OWNERS=$($PSQL_CMD -c "
        SELECT DISTINCT tableowner FROM pg_tables
        WHERE schemaname NOT IN ('pg_catalog', 'information_schema')
        ORDER BY tableowner;
    " 2>/dev/null)

    local SCHEMA_OWNERS=$($PSQL_CMD -c "
        SELECT nspname, pg_catalog.pg_get_userbyid(nspowner) as owner
        FROM pg_namespace
        WHERE nspname NOT LIKE 'pg_%' AND nspname != 'information_schema'
        ORDER BY nspname;
    " 2>/dev/null)

    DT="[테이블 소유자 목록]\n$OBJECT_OWNERS\n\n[스키마 소유자 목록]\n$SCHEMA_OWNERS"

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

    local GRANT_OPTION_USERS=$($PSQL_CMD -c "
        SELECT DISTINCT grantee
        FROM information_schema.role_table_grants
        WHERE is_grantable = 'YES'
        AND grantee NOT IN ('postgres', 'rdsadmin', 'pg_database_owner')
        AND table_schema NOT IN ('pg_catalog', 'information_schema');
    " 2>/dev/null)

    local ALL_GRANT_OPTIONS=$($PSQL_CMD -c "
        SELECT grantee, table_schema, table_name, privilege_type
        FROM information_schema.role_table_grants
        WHERE is_grantable = 'YES'
        AND table_schema NOT IN ('pg_catalog', 'information_schema')
        ORDER BY grantee, table_schema, table_name
        LIMIT 50;
    " 2>/dev/null)

    DT="[GRANT OPTION 현황]\n$ALL_GRANT_OPTIONS"

    if [ -z "$GRANT_OPTION_USERS" ]; then
        RES="Y"
        DESC="일반 사용자에게 GRANT OPTION이 부여되지 않음"
    else
        RES="N"
        DESC="일반 사용자에게 GRANT OPTION이 부여됨"
        DT="[취약 계정 - GRANT OPTION 보유]\n$GRANT_OPTION_USERS\n\n$DT"
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

    local RES="N/A"
    local DESC="N/A (PostgreSQL은 Oracle RESOURCE_LIMIT 파라미터가 없음)"

    DT="해당 항목은 Oracle의 RESOURCE_LIMIT 파라미터를 TRUE로 설정했는지 점검하는 항목입니다.\nPostgreSQL은 Oracle과 같은 RESOURCE_LIMIT 파라미터가 없으므로\n본 항목은 PostgreSQL 환경에서 점검 대상에서 제외됩니다.\n\n※ PostgreSQL의 자원 제한은 다음 방법으로 설정 가능합니다:\n- statement_timeout: 쿼리 실행 시간 제한\n- idle_in_transaction_session_timeout: 유휴 트랜잭션 제한\n- work_mem, maintenance_work_mem: 메모리 사용량 제한\n- max_connections: 최대 연결 수 제한"

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
    local DESC="N/A (PostgreSQL은 MSSQL xp_cmdshell이 없음)"

    DT="해당 항목은 MSSQL의 xp_cmdshell 확장 저장 프로시저 사용을 제한하는 항목입니다.\nPostgreSQL은 MSSQL의 xp_cmdshell이 없으므로\n본 항목은 PostgreSQL 환경에서 점검 대상에서 제외됩니다.\n\n※ PostgreSQL에서 유사한 기능을 제공하는 확장 모듈:\n- COPY TO PROGRAM: 외부 프로그램 실행 (superuser만 사용 가능)\n- plpythonu, plperlu: 신뢰되지 않은 언어 확장"

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
    local DESC="N/A (PostgreSQL은 MSSQL Registry Procedure가 없음)"

    DT="해당 항목은 MSSQL의 xp_regread, xp_regwrite 등 Registry 접근 프로시저의\n권한을 제한하는 항목입니다.\nPostgreSQL은 MSSQL의 Registry Procedure가 없으므로\n본 항목은 PostgreSQL 환경에서 점검 대상에서 제외됩니다.\n\n※ PostgreSQL은 Windows 레지스트리 접근 기능을 제공하지 않습니다."

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

    DT="[현재 버전]\nPostgreSQL $PG_VERSION\n\n[전체 버전 정보]\n$DB_VERSION\n\n※ 최신 버전은 PostgreSQL 공식 사이트에서 확인\nhttps://www.postgresql.org/support/versioning/"

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

    local LOG_COLLECTOR=$($PSQL_CMD -c "SHOW logging_collector;" 2>/dev/null)
    local LOG_STATEMENT=$($PSQL_CMD -c "SHOW log_statement;" 2>/dev/null)
    local LOG_CONNECTIONS=$($PSQL_CMD -c "SHOW log_connections;" 2>/dev/null)
    local LOG_DISCONNECTIONS=$($PSQL_CMD -c "SHOW log_disconnections;" 2>/dev/null)
    local LOG_DIRECTORY=$($PSQL_CMD -c "SHOW log_directory;" 2>/dev/null)
    local LOG_FILENAME=$($PSQL_CMD -c "SHOW log_filename;" 2>/dev/null)

    DT="[로깅 설정]\nlogging_collector = $LOG_COLLECTOR\nlog_statement = $LOG_STATEMENT\nlog_connections = $LOG_CONNECTIONS\nlog_disconnections = $LOG_DISCONNECTIONS\nlog_directory = $LOG_DIRECTORY\nlog_filename = $LOG_FILENAME"

    if [ "$LOG_COLLECTOR" == "on" ]; then
        RES="Y"
        DESC="감사 로그(logging_collector)가 활성화됨"
    else
        RES="N"
        DESC="감사 로그(logging_collector)가 비활성화됨"
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
# PostgreSQL_Linux 보안 진단 스크립트
# KISA 주요정보통신기반시설 기술적 취약점 분석·평가 기준
#================================================================
# 버전  : 2603070
# 대상  : PostgreSQL_Linux
# 항목  : D-01 ~ D-26 (26개)
# 제작  : Seedgen
#================================================================
META_STD="KISA"

#================================================================
# INIT
#================================================================
META_VER="1.0"
META_PLAT="PostgreSQL"
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
echo ""
echo "============================================================"
echo " PostgreSQL 보안 진단 스크립트"
echo "============================================================"
echo ""
echo "[연결 정보 입력]"
echo ""

# psql 클라이언트 확인
PSQL_CLIENT=$(which psql 2>/dev/null)
if [ -z "$PSQL_CLIENT" ]; then
    echo -n "psql Client Path (psql not found): "
    read PSQL_CLIENT
    if [ ! -x "$PSQL_CLIENT" ]; then
        echo "[!] psql 클라이언트를 찾을 수 없습니다."
        exit 1
    fi
fi

# 연결 정보 입력
echo -n "Host (default: localhost): "
read DB_HOST
DB_HOST=${DB_HOST:-localhost}

echo -n "Port (default: 5432): "
read DB_PORT
DB_PORT=${DB_PORT:-5432}

echo -n "Database (default: postgres): "
read DB_NAME
DB_NAME=${DB_NAME:-postgres}

echo -n "User (default: postgres): "
read DB_USER
DB_USER=${DB_USER:-postgres}

echo -n "Password: "
read -s DB_PASS
echo ""

if [ -z "$DB_PASS" ]; then
    echo "[!] 비밀번호를 입력해주세요."
    exit 1
fi

# PostgreSQL 연결 명령어
export PGPASSWORD="$DB_PASS"
PSQL_CMD="$PSQL_CLIENT -h $DB_HOST -p $DB_PORT -U $DB_USER -d $DB_NAME -t -A"

# 연결 테스트
echo ""
echo "[연결 테스트 중...]"
DB_VERSION=$($PSQL_CMD -c "SELECT version();" 2>/dev/null)
if [ $? -ne 0 ]; then
    echo "[!] PostgreSQL 연결 실패"
    exit 1
fi
echo "[OK] PostgreSQL 연결 성공"
echo "    $DB_VERSION"
echo ""

# PostgreSQL 버전 정보
PG_VERSION=$($PSQL_CMD -c "SHOW server_version;" 2>/dev/null)
PG_DATA_DIR=$($PSQL_CMD -c "SHOW data_directory;" 2>/dev/null)

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

    local RES="M"
    local DESC="postgres 계정 비밀번호 변경 여부 수동 확인 필요"

    local USER_LIST=$($PSQL_CMD -c "
        SELECT usename, usesuper, usecreatedb, userepl, passwd IS NOT NULL as has_password
        FROM pg_shadow ORDER BY usename;
    " 2>/dev/null)

    DT="[사용자 목록]\n$USER_LIST\n\n※ postgres 계정의 초기 비밀번호 변경 여부 확인 필요"

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

    local ROLE_LIST=$($PSQL_CMD -c "
        SELECT rolname, rolsuper, rolcreaterole, rolcreatedb, rolcanlogin, rolconnlimit
        FROM pg_roles ORDER BY rolname;
    " 2>/dev/null)

    DT="[역할(계정) 목록 - 불필요 계정 여부 확인 필요]\n$ROLE_LIST"

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

    local RES="M"
    local DESC="비밀번호 정책 수동 확인 필요 (PostgreSQL은 외부 인증 모듈 사용)"

    local PW_SETTINGS=$($PSQL_CMD -c "
        SELECT name, setting FROM pg_settings
        WHERE name IN ('password_encryption', 'scram_iterations');
    " 2>/dev/null)

    local PW_EXPIRY=$($PSQL_CMD -c "
        SELECT rolname, rolvaliduntil FROM pg_roles WHERE rolvaliduntil IS NOT NULL;
    " 2>/dev/null)

    DT="[비밀번호 설정]\n$PW_SETTINGS\n\n[비밀번호 만료 설정된 계정]\n$PW_EXPIRY\n\n※ PostgreSQL은 기본적으로 비밀번호 복잡도 검증 기능이 없음\n※ pgaudit, credcheck 확장 모듈 사용 권장"

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
    local DESC="SUPERUSER 권한 보유 계정 수동 확인 필요"

    local SUPER_USERS=$($PSQL_CMD -c "
        SELECT usename FROM pg_shadow WHERE usesuper = true;
    " 2>/dev/null)

    local ADMIN_ROLES=$($PSQL_CMD -c "
        SELECT rolname, rolsuper, rolcreaterole, rolcreatedb, rolreplication, rolbypassrls
        FROM pg_roles WHERE rolsuper = true OR rolcreaterole = true OR rolcreatedb = true
        ORDER BY rolname;
    " 2>/dev/null)

    DT="[SUPERUSER 권한 보유 계정]\n$SUPER_USERS\n\n[관리 권한 보유 계정]\n$ADMIN_ROLES"

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

    local RES="N/A"
    local DESC="PostgreSQL은 기본적으로 비밀번호 재사용 제한 기능을 제공하지 않음"

    DT="PostgreSQL은 비밀번호 히스토리 관리 기능을 기본 제공하지 않습니다.\n외부 인증 시스템(LDAP, AD 등) 또는 확장 모듈 사용을 권장합니다."

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

    local LOGIN_ROLES=$($PSQL_CMD -c "
        SELECT rolname, rolcanlogin FROM pg_roles
        WHERE rolcanlogin = true ORDER BY rolname;
    " 2>/dev/null)

    DT="[로그인 가능 계정 목록 - 개별 계정 사용 여부 확인 필요]\n$LOGIN_ROLES"

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

    local PG_PROC=$(ps -ef | grep postgres | grep -v grep | head -3)
    local PROC_USER=$(ps -ef | grep "postgres:" | grep -v grep | head -1 | awk '{print $1}')

    DT="[PostgreSQL 프로세스]\n$PG_PROC"

    if [ -z "$PG_PROC" ]; then
        RES="N/A"
        DESC="PostgreSQL 프로세스를 찾을 수 없음"
    elif [ "$PROC_USER" == "root" ]; then
        RES="N"
        DESC="PostgreSQL이 root 권한으로 구동 중"
    else
        RES="Y"
        DESC="PostgreSQL이 일반 계정($PROC_USER)으로 구동 중"
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

    local PW_ENCRYPTION=$($PSQL_CMD -c "SHOW password_encryption;" 2>/dev/null)

    local PW_FORMAT=$($PSQL_CMD -c "
        SELECT usename,
               CASE WHEN passwd LIKE 'SCRAM-SHA-256%' THEN 'SCRAM-SHA-256'
                    WHEN passwd LIKE 'md5%' THEN 'MD5'
                    ELSE 'OTHER' END as pw_type
        FROM pg_shadow WHERE passwd IS NOT NULL;
    " 2>/dev/null)

    DT="[비밀번호 암호화 설정]\npassword_encryption = $PW_ENCRYPTION\n\n[계정별 비밀번호 형식]\n$PW_FORMAT"

    if [ "$PW_ENCRYPTION" == "scram-sha-256" ]; then
        RES="Y"
        DESC="안전한 암호화 알고리즘(SCRAM-SHA-256) 사용 중"
    elif [ "$PW_ENCRYPTION" == "md5" ]; then
        RES="N"
        DESC="MD5 암호화 사용 중 (SCRAM-SHA-256 권장)"
    else
        RES="M"
        DESC="암호화 알고리즘 수동 확인 필요"
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

    local RES="N/A"
    local DESC="PostgreSQL은 기본적으로 로그인 실패 잠금 기능을 제공하지 않음"

    local CONN_LIMIT=$($PSQL_CMD -c "
        SELECT rolname, rolconnlimit FROM pg_roles WHERE rolconnlimit > 0;
    " 2>/dev/null)

    DT="[연결 제한 설정된 계정]\n$CONN_LIMIT\n\n※ PostgreSQL은 로그인 실패 잠금 기능을 기본 제공하지 않음\n※ pg_faillock 확장 또는 운영체제 수준의 제어 권장"

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

    local LISTEN_ADDR=$($PSQL_CMD -c "SHOW listen_addresses;" 2>/dev/null)
    local HBA_FILE=$($PSQL_CMD -c "SHOW hba_file;" 2>/dev/null)

    local HBA_CONTENT=""
    if [ -f "$HBA_FILE" ]; then
        HBA_CONTENT=$(grep -v "^#" "$HBA_FILE" | grep -v "^$" 2>/dev/null)
    fi

    DT="[listen_addresses]\n$LISTEN_ADDR\n\n[pg_hba.conf 위치]\n$HBA_FILE\n\n[pg_hba.conf 접근 제어 설정]\n$HBA_CONTENT"

    if [ "$LISTEN_ADDR" == "*" ]; then
        RES="N"
        DESC="모든 IP에서 접속 가능 (listen_addresses = *)"
    elif [ "$LISTEN_ADDR" == "localhost" ] || [ "$LISTEN_ADDR" == "127.0.0.1" ]; then
        RES="Y"
        DESC="로컬 접속만 허용됨"
    else
        RES="M"
        DESC="접근 제한 설정 수동 확인 필요"
    fi

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

    local RES="M"
    local DESC="시스템 카탈로그 접근 권한 수동 확인 필요"

    local PUBLIC_GRANTS=$($PSQL_CMD -c "
        SELECT nspname, privilege_type FROM information_schema.role_usage_grants
        WHERE grantee = 'PUBLIC' AND object_schema IN ('pg_catalog', 'information_schema')
        LIMIT 20;
    " 2>/dev/null)

    local CATALOG_PRIVS=$($PSQL_CMD -c "
        SELECT grantee, privilege_type FROM information_schema.role_table_grants
        WHERE table_schema = 'pg_catalog' AND grantee != 'postgres'
        LIMIT 20;
    " 2>/dev/null)

    DT="[PUBLIC 스키마 권한]\n$PUBLIC_GRANTS\n\n[pg_catalog 접근 권한]\n$CATALOG_PRIVS\n\n※ PostgreSQL은 기본적으로 시스템 카탈로그 읽기 권한이 PUBLIC에 부여됨"

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

    local RES="N/A"
    local DESC="N/A (PostgreSQL은 리스너 개념이 없음)"

    DT="해당 항목은 Oracle TNS Listener의 비밀번호 설정을 점검하는 항목입니다.\nPostgreSQL은 Oracle과 달리 별도의 리스너(Listener) 프로세스가 없으므로\n본 항목은 PostgreSQL 환경에서 점검 대상에서 제외됩니다."

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
    local DESC="N/A (PostgreSQL은 ODBC/OLE-DB 드라이버 관리가 OS 영역)"

    DT="[N/A 사유]\nPostgreSQL은 데이터베이스 서버이며, ODBC/OLE-DB 데이터 소스 및 드라이버 관리는 클라이언트 OS 영역입니다.\n서버 측에서 점검해야 할 ODBC/OLE-DB 설정이 없으므로, 해당 항목은 적용되지 않습니다.\n\n[참고]\n- ODBC 드라이버: 클라이언트 OS에서 관리 (Windows: ODBC 데이터 원본 관리자)\n- OLE-DB: Windows 클라이언트 전용 기술\n- PostgreSQL 서버는 클라이언트 연결을 수신하는 역할만 수행"

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

    # PostgreSQL 설정 파일 경로 조회
    local CONFIG_FILE=$($PSQL_CMD -t -c "SHOW config_file;" 2>/dev/null | tr -d '[:space:]')
    local HBA_FILE=$($PSQL_CMD -t -c "SHOW hba_file;" 2>/dev/null | tr -d '[:space:]')
    local IDENT_FILE=$($PSQL_CMD -t -c "SHOW ident_file;" 2>/dev/null | tr -d '[:space:]')
    local DATA_DIR=$($PSQL_CMD -t -c "SHOW data_directory;" 2>/dev/null | tr -d '[:space:]')
    local LOG_DIR=$($PSQL_CMD -t -c "SHOW log_directory;" 2>/dev/null | tr -d '[:space:]')

    # 파일 정보 수집 함수
    get_file_info() {
        local filepath="$1"
        if [ -e "$filepath" ]; then
            local perm=$(stat -c "%a" "$filepath" 2>/dev/null)
            local owner=$(stat -c "%U:%G" "$filepath" 2>/dev/null)
            echo "경로: $filepath"
            echo "권한: $perm"
            echo "소유자: $owner"
        else
            echo "경로: $filepath (파일 없음)"
        fi
    }

    DT="[postgresql.conf]\n"
    if [ -n "$CONFIG_FILE" ]; then
        DT="${DT}$(get_file_info "$CONFIG_FILE")"
    else
        DT="${DT}경로 확인 불가"
    fi

    DT="${DT}\n\n[pg_hba.conf]\n"
    if [ -n "$HBA_FILE" ]; then
        DT="${DT}$(get_file_info "$HBA_FILE")"
    else
        DT="${DT}경로 확인 불가"
    fi

    DT="${DT}\n\n[pg_ident.conf]\n"
    if [ -n "$IDENT_FILE" ]; then
        DT="${DT}$(get_file_info "$IDENT_FILE")"
    else
        DT="${DT}경로 확인 불가"
    fi

    DT="${DT}\n\n[data 디렉터리]\n"
    if [ -d "$DATA_DIR" ]; then
        DT="${DT}$(get_file_info "$DATA_DIR")"
    else
        DT="${DT}경로 확인 불가"
    fi

    # 로그 파일 권한 확인
    DT="${DT}\n\n[로그 디렉터리]\n"
    local FULL_LOG_DIR="$LOG_DIR"
    # 상대 경로인 경우 data_directory 기준으로 변환
    if [ -n "$LOG_DIR" ] && [[ ! "$LOG_DIR" = /* ]]; then
        FULL_LOG_DIR="${DATA_DIR}/${LOG_DIR}"
    fi
    if [ -d "$FULL_LOG_DIR" ]; then
        DT="${DT}$(get_file_info "$FULL_LOG_DIR")\n"
        # 최근 로그 파일 샘플 확인
        local LOG_FILES=$(ls -la "$FULL_LOG_DIR"/*.log 2>/dev/null | head -3)
        if [ -n "$LOG_FILES" ]; then
            DT="${DT}\n[로그 파일 샘플]\n$LOG_FILES"
        fi
    else
        DT="${DT}경로: $FULL_LOG_DIR (디렉터리 없음)"
    fi

    # 권한 검사
    local INSECURE=0
    for file in "$CONFIG_FILE" "$HBA_FILE"; do
        if [ -f "$file" ]; then
            local PERM=$(stat -c "%a" "$file" 2>/dev/null)
            if [ -n "$PERM" ]; then
                local OTHER_WRITE=$((PERM % 10))
                local GROUP_WRITE=$(((PERM / 10) % 10))
                if [ $((OTHER_WRITE & 2)) -ne 0 ] || [ $((GROUP_WRITE & 2)) -ne 0 ]; then
                    INSECURE=1
                fi
            fi
        fi
    done

    if [ $INSECURE -eq 0 ]; then
        RES="Y"
        DESC="주요 설정 파일 권한이 적절함"
    else
        RES="N"
        DESC="주요 설정 파일에 과도한 권한 존재"
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

    local RES="N/A"
    local DESC="N/A (PostgreSQL은 Oracle trace 파일이 없음)"

    DT="해당 항목은 Oracle Listener의 로그 및 trace 파일에 대한 접근 권한을 점검하는 항목입니다.\nPostgreSQL은 Oracle과 달리 별도의 리스너(Listener) 프로세스와 trace 파일이 없으므로\n본 항목은 PostgreSQL 환경에서 점검 대상에서 제외됩니다.\n\n※ PostgreSQL의 로그 파일 권한은 D-14 항목에서 점검합니다."

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
    local DESC="N/A (PostgreSQL은 Windows 인증 모드가 없음)"

    DT="해당 항목은 MSSQL의 Windows 통합 인증 사용 여부를 점검하는 항목입니다.\nPostgreSQL은 MSSQL의 Windows 인증 모드 개념이 없으므로\n본 항목은 PostgreSQL 환경에서 점검 대상에서 제외됩니다.\n\n※ PostgreSQL은 pg_hba.conf를 통해 인증 방식을 설정합니다.\n※ LDAP, GSSAPI, SSPI 등 다양한 인증 방식을 지원합니다."

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

    local RES="N/A"
    local DESC="N/A (PostgreSQL은 Oracle AUD$ 테이블이 없음)"

    DT="해당 항목은 Oracle의 AUD$ 감사 테이블에 대한 접근 권한을 점검하는 항목입니다.\nPostgreSQL은 Oracle과 같은 AUD$ 테이블이 없으므로\n본 항목은 PostgreSQL 환경에서 점검 대상에서 제외됩니다.\n\n※ PostgreSQL의 감사 기능은 pgaudit 확장 또는 log_statement 설정을 사용합니다."

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

    local RES="N/A"
    local DESC="N/A (PostgreSQL은 Oracle PUBLIC 롤 개념이 다름)"

    DT="해당 항목은 Oracle의 PUBLIC 롤에 부여된 권한을 점검하는 항목입니다.\nPostgreSQL은 public 스키마에 대한 기본 권한 관리 방식이 Oracle과 다르므로\n본 항목은 PostgreSQL 환경에서 점검 대상에서 제외됩니다.\n\n※ PostgreSQL의 public 스키마 권한은 D-11 항목에서 점검합니다.\n※ REVOKE ALL ON SCHEMA public FROM PUBLIC; 명령으로 제한 가능합니다."

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

    local RES="N/A"
    local DESC="N/A (PostgreSQL은 Oracle OS_ROLES 파라미터가 없음)"

    DT="해당 항목은 Oracle의 OS_ROLES, REMOTE_OS_AUTHENT, REMOTE_OS_ROLES 파라미터를\nFALSE로 설정했는지 점검하는 항목입니다.\nPostgreSQL은 이러한 파라미터가 없으므로\n본 항목은 PostgreSQL 환경에서 점검 대상에서 제외됩니다.\n\n※ PostgreSQL의 OS 인증은 pg_hba.conf의 peer/ident 방식으로 관리됩니다."

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

    local OBJECT_OWNERS=$($PSQL_CMD -c "
        SELECT DISTINCT tableowner FROM pg_tables
        WHERE schemaname NOT IN ('pg_catalog', 'information_schema')
        ORDER BY tableowner;
    " 2>/dev/null)

    local SCHEMA_OWNERS=$($PSQL_CMD -c "
        SELECT nspname, pg_catalog.pg_get_userbyid(nspowner) as owner
        FROM pg_namespace
        WHERE nspname NOT LIKE 'pg_%' AND nspname != 'information_schema'
        ORDER BY nspname;
    " 2>/dev/null)

    DT="[테이블 소유자 목록]\n$OBJECT_OWNERS\n\n[스키마 소유자 목록]\n$SCHEMA_OWNERS"

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

    local GRANT_OPTION_USERS=$($PSQL_CMD -c "
        SELECT DISTINCT grantee
        FROM information_schema.role_table_grants
        WHERE is_grantable = 'YES'
        AND grantee NOT IN ('postgres', 'rdsadmin', 'pg_database_owner')
        AND table_schema NOT IN ('pg_catalog', 'information_schema');
    " 2>/dev/null)

    local ALL_GRANT_OPTIONS=$($PSQL_CMD -c "
        SELECT grantee, table_schema, table_name, privilege_type
        FROM information_schema.role_table_grants
        WHERE is_grantable = 'YES'
        AND table_schema NOT IN ('pg_catalog', 'information_schema')
        ORDER BY grantee, table_schema, table_name
        LIMIT 50;
    " 2>/dev/null)

    DT="[GRANT OPTION 현황]\n$ALL_GRANT_OPTIONS"

    if [ -z "$GRANT_OPTION_USERS" ]; then
        RES="Y"
        DESC="일반 사용자에게 GRANT OPTION이 부여되지 않음"
    else
        RES="N"
        DESC="일반 사용자에게 GRANT OPTION이 부여됨"
        DT="[취약 계정 - GRANT OPTION 보유]\n$GRANT_OPTION_USERS\n\n$DT"
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

    local RES="N/A"
    local DESC="N/A (PostgreSQL은 Oracle RESOURCE_LIMIT 파라미터가 없음)"

    DT="해당 항목은 Oracle의 RESOURCE_LIMIT 파라미터를 TRUE로 설정했는지 점검하는 항목입니다.\nPostgreSQL은 Oracle과 같은 RESOURCE_LIMIT 파라미터가 없으므로\n본 항목은 PostgreSQL 환경에서 점검 대상에서 제외됩니다.\n\n※ PostgreSQL의 자원 제한은 다음 방법으로 설정 가능합니다:\n- statement_timeout: 쿼리 실행 시간 제한\n- idle_in_transaction_session_timeout: 유휴 트랜잭션 제한\n- work_mem, maintenance_work_mem: 메모리 사용량 제한\n- max_connections: 최대 연결 수 제한"

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
    local DESC="N/A (PostgreSQL은 MSSQL xp_cmdshell이 없음)"

    DT="해당 항목은 MSSQL의 xp_cmdshell 확장 저장 프로시저 사용을 제한하는 항목입니다.\nPostgreSQL은 MSSQL의 xp_cmdshell이 없으므로\n본 항목은 PostgreSQL 환경에서 점검 대상에서 제외됩니다.\n\n※ PostgreSQL에서 유사한 기능을 제공하는 확장 모듈:\n- COPY TO PROGRAM: 외부 프로그램 실행 (superuser만 사용 가능)\n- plpythonu, plperlu: 신뢰되지 않은 언어 확장"

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
    local DESC="N/A (PostgreSQL은 MSSQL Registry Procedure가 없음)"

    DT="해당 항목은 MSSQL의 xp_regread, xp_regwrite 등 Registry 접근 프로시저의\n권한을 제한하는 항목입니다.\nPostgreSQL은 MSSQL의 Registry Procedure가 없으므로\n본 항목은 PostgreSQL 환경에서 점검 대상에서 제외됩니다.\n\n※ PostgreSQL은 Windows 레지스트리 접근 기능을 제공하지 않습니다."

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

    DT="[현재 버전]\nPostgreSQL $PG_VERSION\n\n[전체 버전 정보]\n$DB_VERSION\n\n※ 최신 버전은 PostgreSQL 공식 사이트에서 확인\nhttps://www.postgresql.org/support/versioning/"

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

    local LOG_COLLECTOR=$($PSQL_CMD -c "SHOW logging_collector;" 2>/dev/null)
    local LOG_STATEMENT=$($PSQL_CMD -c "SHOW log_statement;" 2>/dev/null)
    local LOG_CONNECTIONS=$($PSQL_CMD -c "SHOW log_connections;" 2>/dev/null)
    local LOG_DISCONNECTIONS=$($PSQL_CMD -c "SHOW log_disconnections;" 2>/dev/null)
    local LOG_DIRECTORY=$($PSQL_CMD -c "SHOW log_directory;" 2>/dev/null)
    local LOG_FILENAME=$($PSQL_CMD -c "SHOW log_filename;" 2>/dev/null)

    DT="[로깅 설정]\nlogging_collector = $LOG_COLLECTOR\nlog_statement = $LOG_STATEMENT\nlog_connections = $LOG_CONNECTIONS\nlog_disconnections = $LOG_DISCONNECTIONS\nlog_directory = $LOG_DIRECTORY\nlog_filename = $LOG_FILENAME"

    if [ "$LOG_COLLECTOR" == "on" ]; then
        RES="Y"
        DESC="감사 로그(logging_collector)가 활성화됨"
    else
        RES="N"
        DESC="감사 로그(logging_collector)가 비활성화됨"
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
