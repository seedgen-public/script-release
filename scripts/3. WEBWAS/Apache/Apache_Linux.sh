#!/bin/bash
#================================================================
# Apache_Linux 보안 진단 스크립트
# KISA 주요정보통신기반시설 기술적 취약점 분석·평가 기준
#================================================================
# 버전  : 2603070
# 대상  : Apache_Linux
# 항목  : WEB-01 ~ WEB-26 (26개)
# 제작  : Seedgen
#================================================================
META_STD="KISA"

# Apache 설치 경로 (자동 탐지 실패 시 수동 설정)
APACHE_HOME=""
APACHE_CONF=""

#================================================================
# INIT
#================================================================
META_VER="1.0"
META_PLAT="Apache"
META_TYPE="WEB"

# 권한 체크
if [ "$EUID" -ne 0 ]; then
    echo "[!] root 권한으로 실행하세요."
    exit 1
fi

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
# COLLECT
#================================================================
META_DATE=$(date +%Y-%m-%dT%H:%M:%S%:z)
SYS_HOST=$(hostname)
SYS_DOM=$(hostname -d 2>/dev/null || echo "N/A")
SYS_OS_NAME=$(grep PRETTY_NAME /etc/os-release 2>/dev/null | cut -d'"' -f2)
SYS_OS_FN=$(echo "$SYS_OS_NAME" | sed 's/ (.*)//g')
SYS_KN=$(uname -r)
SYS_ARCH=$(uname -m)
SYS_IP=$(hostname -I 2>/dev/null | awk '{print $1}')
SYS_NET_ALL=$(ip -4 addr show 2>/dev/null | grep inet | awk '{print $NF": "$2}' | cut -d'/' -f1)

#================================================================
# DETECT — 플랫폼별 커스터마이즈 영역
# (서비스 탐지, 설정파일 경로, 버전 정보)
#================================================================
# Apache 설치 경로 자동 탐지
detect_apache() {
    local APACHE_BIN=""

    # httpd 또는 apache2 바이너리 찾기
    if command -v httpd &>/dev/null; then
        APACHE_BIN="httpd"
    elif command -v apache2 &>/dev/null; then
        APACHE_BIN="apache2"
    elif command -v apachectl &>/dev/null; then
        APACHE_BIN="apachectl"
    fi

    if [ -n "$APACHE_BIN" ]; then
        # 설정 파일 경로 추출
        APACHE_CONF=$($APACHE_BIN -V 2>/dev/null | grep "SERVER_CONFIG_FILE" | cut -d'"' -f2)

        # 절대 경로가 아니면 HTTPD_ROOT와 조합
        if [[ ! "$APACHE_CONF" == /* ]]; then
            local HTTPD_ROOT=$($APACHE_BIN -V 2>/dev/null | grep "HTTPD_ROOT" | cut -d'"' -f2)
            APACHE_CONF="${HTTPD_ROOT}/${APACHE_CONF}"
        fi

        # APACHE_HOME 설정
        APACHE_HOME=$(dirname "$APACHE_CONF")
    fi

    # 일반적인 경로에서 찾기
    if [ -z "$APACHE_CONF" ] || [ ! -f "$APACHE_CONF" ]; then
        local COMMON_PATHS=(
            "/etc/httpd/conf/httpd.conf"
            "/etc/apache2/apache2.conf"
            "/usr/local/apache2/conf/httpd.conf"
            "/opt/apache/conf/httpd.conf"
        )
        for path in "${COMMON_PATHS[@]}"; do
            if [ -f "$path" ]; then
                APACHE_CONF="$path"
                APACHE_HOME=$(dirname "$APACHE_CONF")
                break
            fi
        done
    fi
}

# Apache 탐지 실행
detect_apache

# Apache 버전 정보
APACHE_VERSION=""
if command -v httpd &>/dev/null; then
    APACHE_VERSION=$(httpd -v 2>/dev/null | head -1)
elif command -v apache2 &>/dev/null; then
    APACHE_VERSION=$(apache2 -v 2>/dev/null | head -1)
fi

SVC_VERSION="$APACHE_VERSION"
SVC_CONF="$APACHE_CONF"

# 출력 파일 경로
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
OUTPUT_FILE="${SCRIPT_DIR}/${META_PLAT}_${SYS_HOST}_$(date +%Y%m%d_%H%M%S).xml"

#================================================================
# CHECK FUNCTIONS
#================================================================

check01() {
    local CODE="WEB-01"
    local CAT="계정관리"
    local NAME="Default 관리자 계정명 변경"
    local IMP="상"
    local STD="관리자 페이지를 사용하지 않거나, 계정명이 기본 계정명으로 설정되어 있지 않은 경우"
    local RES=""
    local DESC=""
    local DT=""

    local RES="N/A"
    local DESC="Apache는 별도의 관리자 계정이 존재하지 않아 해당 없음"
    local DT="Apache HTTP Server는 IIS나 Tomcat과 달리 별도의 관리 콘솔 및 관리자 계정이 없습니다.\n서버 관리는 설정 파일(httpd.conf) 편집을 통해 이루어지며, 파일 시스템 권한으로 접근을 제어합니다."

    output_checkpoint "$CODE" "$CAT" "$NAME" "$IMP" "$STD" "$RES" "$DESC" "$DT"
}

check02() {
    local CODE="WEB-02"
    local CAT="계정관리"
    local NAME="취약한 비밀번호 사용 제한"
    local IMP="상"
    local STD="관리자 비밀번호가 암호화되어 있거나, 유추하기 어려운 비밀번호로 설정된 경우"
    local RES=""
    local DESC=""
    local DT=""

    local RES="N/A"
    local DESC="Apache는 별도의 내장 인증 계정이 존재하지 않아 해당 없음"
    local DT="Apache HTTP Server는 내장된 인증 계정 시스템이 없습니다.\n기본 인증(Basic Auth)을 사용할 경우 .htpasswd 파일을 별도로 구성하며, 이는 WEB-03 항목에서 선택적으로 점검합니다."

    output_checkpoint "$CODE" "$CAT" "$NAME" "$IMP" "$STD" "$RES" "$DESC" "$DT"
}

check03() {
    local CODE="WEB-03"
    local CAT="계정관리"
    local NAME="비밀번호 파일 권한 관리"
    local IMP="상"
    local STD="비밀번호 파일에 권한이 600 이하로 설정된 경우"
    local RES=""
    local DESC=""
    local DT=""

    local RES="N/A"
    local DESC="Apache는 별도의 비밀번호 파일을 사용하지 않아 해당 없음"
    local DT="Apache HTTP Server는 기본적으로 비밀번호 파일을 사용하지 않습니다.\n.htpasswd 파일은 Basic 인증 사용 시 선택적으로 구성되며, 대부분의 환경에서는 애플리케이션 레벨에서 인증을 처리합니다."

    output_checkpoint "$CODE" "$CAT" "$NAME" "$IMP" "$STD" "$RES" "$DESC" "$DT"
}

check04() {
    local CODE="WEB-04"
    local CAT="서비스관리"
    local NAME="웹 서비스 디렉터리 리스팅 방지 설정"
    local IMP="상"
    local STD="디렉터리 리스팅이 설정되지 않은 경우"
    local RES=""
    local DESC=""
    local DT=""

    if [ -z "$APACHE_CONF" ] || [ ! -f "$APACHE_CONF" ]; then
        RES="N/A"
        DESC="Apache 설정 파일이 존재하지 않아 해당 없음"
        DT="APACHE_CONF: not found"
    else
        # Options Indexes 설정 확인 (설정 디렉터리 + mods-enabled/sites-enabled)
        local CONF_DIR=$(dirname "$APACHE_CONF")
        local SEARCH_DIRS="$CONF_DIR"
        [ -d "$CONF_DIR/mods-enabled" ] && SEARCH_DIRS="$SEARCH_DIRS $CONF_DIR/mods-enabled"
        [ -d "$CONF_DIR/sites-enabled" ] && SEARCH_DIRS="$SEARCH_DIRS $CONF_DIR/sites-enabled"
        [ -d "$CONF_DIR/conf-enabled" ] && SEARCH_DIRS="$SEARCH_DIRS $CONF_DIR/conf-enabled"
        local INDEXES_ON=$(grep -rnE "^\s*Options.*\+?Indexes" $SEARCH_DIRS --include="*.conf" 2>/dev/null | grep -v "^\s*#" | grep -v "\-Indexes")

        if [ -z "$INDEXES_ON" ]; then
            RES="Y"
            DESC="Options Indexes가 설정되지 않아 디렉터리 리스팅이 비활성화되어 양호"
            DT="Options Indexes: 미설정 또는 -Indexes"
        else
            RES="N"
            DESC="Options Indexes가 설정되어 디렉터리 리스팅이 활성화되어 취약"
            DT="발견된 설정:\n$INDEXES_ON"
        fi
    fi

    output_checkpoint "$CODE" "$CAT" "$NAME" "$IMP" "$STD" "$RES" "$DESC" "$DT"
}

check05() {
    local CODE="WEB-05"
    local CAT="서비스관리"
    local NAME="지정하지 않은 CGI/ISAPI 실행 제한"
    local IMP="상"
    local STD="CGI 스크립트를 사용하지 않거나 CGI 스크립트가 실행 가능한 디렉터리를 제한한 경우"
    local RES=""
    local DESC=""
    local DT=""

    if [ -z "$APACHE_CONF" ] || [ ! -f "$APACHE_CONF" ]; then
        RES="N/A"
        DESC="Apache 설정 파일이 존재하지 않아 해당 없음"
        DT="APACHE_CONF: not found"
    else
        local CONF_DIR=$(dirname "$APACHE_CONF")

        # CGI 모듈 활성화 확인
        local CGI_MODULE=$(grep -rE "^\s*LoadModule.*(cgi_module|cgid_module)" "$CONF_DIR" --include="*.conf" 2>/dev/null | grep -v "^\s*#")

        # ExecCGI 옵션 확인
        local EXEC_CGI=$(grep -rE "^\s*Options.*\+?ExecCGI" "$CONF_DIR" --include="*.conf" 2>/dev/null | grep -v "^\s*#" | grep -v "\-ExecCGI")

        # ScriptAlias 설정 확인 (CGI 실행을 허용하는 디렉티브)
        local SCRIPT_ALIAS=$(grep -rE "^\s*ScriptAlias" "$CONF_DIR" --include="*.conf" 2>/dev/null | grep -v "^\s*#")

        # 상세 정보 구성
        local DETAILS=""
        if [ -n "$CGI_MODULE" ]; then
            DETAILS="[CGI 모듈] 활성화\n$CGI_MODULE\n"
        else
            DETAILS="[CGI 모듈] 비활성화\n"
        fi

        if [ -n "$SCRIPT_ALIAS" ]; then
            DETAILS="${DETAILS}\n[ScriptAlias 설정] (CGI 경로 제한)\n$SCRIPT_ALIAS\n"
        else
            DETAILS="${DETAILS}\n[ScriptAlias 설정] 없음\n"
        fi

        if [ -n "$EXEC_CGI" ]; then
            DETAILS="${DETAILS}\n[ExecCGI 설정]\n$EXEC_CGI"
        else
            DETAILS="${DETAILS}\n[ExecCGI 설정] 없음"
        fi

        # 판정 로직
        if [ -z "$CGI_MODULE" ] && [ -z "$EXEC_CGI" ] && [ -z "$SCRIPT_ALIAS" ]; then
            RES="Y"
            DESC="CGI 관련 설정이 존재하지 않아 CGI 실행이 제한되어 양호"
            DT="$DETAILS"
        elif [ -z "$CGI_MODULE" ]; then
            # CGI 모듈이 비활성화되어 있으면 양호
            RES="Y"
            DESC="CGI 모듈이 비활성화되어 CGI 실행이 제한되어 양호"
            DT="$DETAILS"
        elif [ -n "$SCRIPT_ALIAS" ] && [ -z "$EXEC_CGI" ]; then
            # ScriptAlias만 있고 ExecCGI가 없으면 CGI 실행이 지정 경로로 제한됨
            RES="Y"
            DESC="ScriptAlias로 CGI 실행 경로가 제한되어 양호"
            DT="$DETAILS"
        elif [ -n "$EXEC_CGI" ]; then
            # ExecCGI가 있으면 수동 확인 필요
            RES="M"
            DESC="ExecCGI 설정이 존재하여 CGI 실행 범위 수동 확인 필요"
            DT="$DETAILS\n\n[참고] ExecCGI가 DocumentRoot 또는 넓은 범위에 설정되어 있는지 확인하세요."
        else
            RES="M"
            DESC="CGI 설정이 존재하여 수동 확인 필요"
            DT="$DETAILS"
        fi
    fi

    output_checkpoint "$CODE" "$CAT" "$NAME" "$IMP" "$STD" "$RES" "$DESC" "$DT"
}

check06() {
    local CODE="WEB-06"
    local CAT="서비스관리"
    local NAME="웹 서비스 상위 디렉터리 접근 제한 설정"
    local IMP="상"
    local STD="상위 디렉터리 접근 기능을 제거한 경우"
    local RES=""
    local DESC=""
    local DT=""

    if [ -z "$APACHE_CONF" ] || [ ! -f "$APACHE_CONF" ]; then
        RES="N/A"
        DESC="Apache 설정 파일이 존재하지 않아 해당 없음"
        DT="APACHE_CONF: not found"
    else
        local CONF_DIR=$(dirname "$APACHE_CONF")

        # AllowOverride 설정 확인 (enabled 디렉터리 포함)
        local SEARCH_DIRS="$CONF_DIR"
        [ -d "$CONF_DIR/mods-enabled" ] && SEARCH_DIRS="$SEARCH_DIRS $CONF_DIR/mods-enabled"
        [ -d "$CONF_DIR/sites-enabled" ] && SEARCH_DIRS="$SEARCH_DIRS $CONF_DIR/sites-enabled"
        [ -d "$CONF_DIR/conf-enabled" ] && SEARCH_DIRS="$SEARCH_DIRS $CONF_DIR/conf-enabled"
        local ALLOW_OVERRIDE=$(grep -rnE "^\s*AllowOverride" $SEARCH_DIRS --include="*.conf" 2>/dev/null | grep -v "^\s*#")

        # AllowOverride 설정 판정:
        # - All이 있으면 취약 (모든 .htaccess 지시자 허용)
        # - None만 있으면 양호 (.htaccess 무시)
        # - None과 함께 AuthConfig/FileInfo 등 혼재 시 수동확인 (특정 디렉터리 필요성 검토)
        local NONE_COUNT=$(echo "$ALLOW_OVERRIDE" | grep -ci "None")
        local ALL_COUNT=$(echo "$ALLOW_OVERRIDE" | grep -cE "\bAll\b")
        local PARTIAL_COUNT=$(echo "$ALLOW_OVERRIDE" | grep -iE "(AuthConfig|FileInfo|Indexes|Limit)" | grep -vc "None")

        if [ -n "$ALLOW_OVERRIDE" ]; then
            if [ "$ALL_COUNT" -gt 0 ]; then
                RES="N"
                DESC="AllowOverride All이 설정되어 .htaccess를 통한 모든 설정 변경이 가능하여 취약"
                DT="AllowOverride 설정:\n$ALLOW_OVERRIDE\n\n[취약] All 설정 시 .htaccess를 통한 모든 설정 변경이 가능합니다."
            elif [ "$NONE_COUNT" -gt 0 ] && [ "$PARTIAL_COUNT" -eq 0 ]; then
                RES="Y"
                DESC="AllowOverride None으로 설정되어 상위 디렉터리 접근이 제한되어 양호"
                DT="AllowOverride 설정:\n$ALLOW_OVERRIDE"
            elif [ "$NONE_COUNT" -gt 0 ] && [ "$PARTIAL_COUNT" -gt 0 ]; then
                RES="M"
                DESC="AllowOverride가 디렉터리별로 혼재 설정되어 수동 확인 필요"
                DT="AllowOverride 설정:\n$ALLOW_OVERRIDE\n\n[참고] 일부 디렉터리에서 AuthConfig/FileInfo 등이 설정되어 있습니다.\n해당 디렉터리의 설정 필요성을 검토하세요."
            else
                RES="M"
                DESC="AllowOverride가 부분 설정되어 수동 확인 필요"
                DT="AllowOverride 설정:\n$ALLOW_OVERRIDE"
            fi
        else
            RES="M"
            DESC="AllowOverride 설정이 존재하지 않아 수동 확인 필요"
            DT="AllowOverride: 미설정"
        fi
    fi

    output_checkpoint "$CODE" "$CAT" "$NAME" "$IMP" "$STD" "$RES" "$DESC" "$DT"
}

check07() {
    local CODE="WEB-07"
    local CAT="서비스관리"
    local NAME="웹 서비스 경로 내 불필요한 파일 제거"
    local IMP="중"
    local STD="기본으로 생성되는 불필요한 파일 및 디렉터리가 존재하지 않을 경우"
    local RES=""
    local DESC=""
    local DT=""

    # 매뉴얼 디렉터리 확인
    local MANUAL_PATHS=(
        "/var/www/html/manual"
        "/usr/share/httpd/manual"
        "/etc/httpd/htdocs/manual"
        "/usr/local/apache2/htdocs/manual"
    )

    local FOUND_MANUAL=""
    for path in "${MANUAL_PATHS[@]}"; do
        if [ -d "$path" ]; then
            FOUND_MANUAL="$FOUND_MANUAL\n$path"
        fi
    done

    # DocumentRoot에서 불필요한 파일 확인
    local DOC_ROOT=""
    if [ -n "$APACHE_CONF" ] && [ -f "$APACHE_CONF" ]; then
        DOC_ROOT=$(grep -E "^\s*DocumentRoot" "$APACHE_CONF" 2>/dev/null | head -1 | awk '{print $2}' | tr -d '"')
    fi

    local UNNECESSARY_FILES=""
    if [ -n "$DOC_ROOT" ] && [ -d "$DOC_ROOT" ]; then
        UNNECESSARY_FILES=$(find "$DOC_ROOT" -type f \( -name "*.bak" -o -name "*.backup" -o -name "*.old" -o -name "*.tmp" -o -name "*.swp" -o -name "*.txt" -o -name "README*" \) 2>/dev/null | head -10)
    fi

    if [ -z "$FOUND_MANUAL" ] && [ -z "$UNNECESSARY_FILES" ]; then
        RES="Y"
        DESC="기본 생성 불필요 파일 및 디렉터리가 존재하지 않아 양호"
        DT="매뉴얼 디렉터리: 없음\n불필요 파일: 없음"
    else
        RES="N"
        DESC="불필요한 파일 또는 디렉터리가 존재하여 취약"
        DT="매뉴얼 디렉터리:$FOUND_MANUAL\n불필요 파일:\n$UNNECESSARY_FILES"
    fi

    output_checkpoint "$CODE" "$CAT" "$NAME" "$IMP" "$STD" "$RES" "$DESC" "$DT"
}

check08() {
    local CODE="WEB-08"
    local CAT="서비스관리"
    local NAME="웹 서비스 파일 업로드 및 다운로드 용량 제한"
    local IMP="하"
    local STD="파일 업로드 및 다운로드 용량을 제한한 경우"
    local RES=""
    local DESC=""
    local DT=""

    if [ -z "$APACHE_CONF" ] || [ ! -f "$APACHE_CONF" ]; then
        RES="N/A"
        DESC="Apache 설정 파일이 존재하지 않아 해당 없음"
        DT="APACHE_CONF: not found"
    else
        local CONF_DIR=$(dirname "$APACHE_CONF")

        # LimitRequestBody 설정 확인 (enabled 디렉터리 포함)
        local SEARCH_DIRS="$CONF_DIR"
        [ -d "$CONF_DIR/sites-enabled" ] && SEARCH_DIRS="$SEARCH_DIRS $CONF_DIR/sites-enabled"
        [ -d "$CONF_DIR/conf-enabled" ] && SEARCH_DIRS="$SEARCH_DIRS $CONF_DIR/conf-enabled"
        local LIMIT_BODY=$(grep -rnE "^\s*LimitRequestBody" $SEARCH_DIRS --include="*.conf" 2>/dev/null | grep -v "^\s*#")

        if [ -n "$LIMIT_BODY" ]; then
            # LimitRequestBody 0 이면 제한 없음 (취약)
            local LIMIT_VAL=$(echo "$LIMIT_BODY" | head -1 | grep -oE '[0-9]+$')
            if [ "$LIMIT_VAL" = "0" ]; then
                RES="N"
                DESC="LimitRequestBody가 0으로 설정되어 파일 업로드 용량 제한이 없어 취약"
                DT="$LIMIT_BODY\n\n※ LimitRequestBody 0은 용량 제한이 없는 설정입니다."
            else
                RES="M"
                DESC="LimitRequestBody가 설정되어 파일 업로드 용량이 제한됨, 수동 확인 필요"
                DT="$LIMIT_BODY"
            fi
        else
            RES="N"
            DESC="LimitRequestBody가 설정되지 않아 파일 업로드 용량 제한이 없어 취약"
            DT="LimitRequestBody: 미설정 (기본값: 제한 없음)"
        fi
    fi

    output_checkpoint "$CODE" "$CAT" "$NAME" "$IMP" "$STD" "$RES" "$DESC" "$DT"
}

check09() {
    local CODE="WEB-09"
    local CAT="서비스관리"
    local NAME="웹 서비스 프로세스 권한 제한"
    local IMP="상"
    local STD="웹 프로세스(웹 서비스)가 관리자 권한이 부여된 계정이 아닌 운영에 필요한 최소한의 권한을 가진 별도의 계정으로 구동되고 있는 경우"
    local RES=""
    local DESC=""
    local DT=""

    # Apache 프로세스 실행 계정 확인
    local APACHE_USER=$(ps aux 2>/dev/null | grep -E "(httpd|apache2)" | grep -v grep | grep -v root | awk '{print $1}' | sort -u | head -1)

    # 설정 파일에서 User/Group 확인
    local CONF_USER=""
    local CONF_GROUP=""
    local CONF_USER_RAW=""
    local CONF_GROUP_RAW=""

    if [ -n "$APACHE_CONF" ] && [ -f "$APACHE_CONF" ]; then
        CONF_USER_RAW=$(grep -E "^\s*User\s+" "$APACHE_CONF" 2>/dev/null | grep -v "^\s*#" | awk '{print $2}')
        CONF_GROUP_RAW=$(grep -E "^\s*Group\s+" "$APACHE_CONF" 2>/dev/null | grep -v "^\s*#" | awk '{print $2}')
        CONF_USER="$CONF_USER_RAW"
        CONF_GROUP="$CONF_GROUP_RAW"
    fi

    # envvars 파일 확인 (Debian/Ubuntu) - 변수 치환 처리
    local ENVVARS_FILE="/etc/apache2/envvars"
    if [ -f "$ENVVARS_FILE" ]; then
        # CONF_USER가 변수 형태(${...} 또는 $...)이거나 비어있으면 envvars에서 실제 값 가져오기
        if [ -z "$CONF_USER" ] || [[ "$CONF_USER" == *'$'* ]] || [[ "$CONF_USER" == *'{'* ]]; then
            # source로 환경변수 로드 후 확인 (서브쉘에서 실행)
            local ENVVARS_USER=$(bash -c "source $ENVVARS_FILE 2>/dev/null && echo \$APACHE_RUN_USER")
            local ENVVARS_GROUP=$(bash -c "source $ENVVARS_FILE 2>/dev/null && echo \$APACHE_RUN_GROUP")

            if [ -n "$ENVVARS_USER" ]; then
                CONF_USER="$ENVVARS_USER"
            fi
            if [ -n "$ENVVARS_GROUP" ]; then
                CONF_GROUP="$ENVVARS_GROUP"
            fi
        fi
    fi

    local CHECK_USER="${APACHE_USER:-$CONF_USER}"

    if [ -z "$CHECK_USER" ]; then
        RES="M"
        DESC="Apache 실행 계정을 확인할 수 없어 수동 확인 필요"
        DT="실행 중인 프로세스: 없음\n설정 파일 User: ${CONF_USER:-미설정}"
    elif [ "$CHECK_USER" = "root" ]; then
        RES="N"
        DESC="Apache가 root 계정으로 실행되어 취약"
        DT="실행 계정: $CHECK_USER"
    else
        RES="Y"
        DESC="Apache가 비root 계정으로 실행되어 양호"
        DT="실행 계정: $CHECK_USER\n설정 User: ${CONF_USER:-미설정}\n설정 Group: ${CONF_GROUP:-미설정}"
    fi

    output_checkpoint "$CODE" "$CAT" "$NAME" "$IMP" "$STD" "$RES" "$DESC" "$DT"
}

check10() {
    local CODE="WEB-10"
    local CAT="서비스관리"
    local NAME="불필요한 프록시 설정 제한"
    local IMP="상"
    local STD="불필요한 Proxy 설정을 제한한 경우"
    local RES=""
    local DESC=""
    local DT=""

    if [ -z "$APACHE_CONF" ] || [ ! -f "$APACHE_CONF" ]; then
        RES="N/A"
        DESC="Apache 설정 파일이 존재하지 않아 해당 없음"
        DT="APACHE_CONF: not found"
    else
        local CONF_DIR=$(dirname "$APACHE_CONF")

        # Proxy 모듈 및 설정 확인
        local PROXY_MODULE=$(grep -rE "^\s*LoadModule.*proxy_module" "$CONF_DIR" --include="*.conf" 2>/dev/null | grep -v "^\s*#")
        local PROXY_PASS=$(grep -rE "^\s*ProxyPass" "$CONF_DIR" --include="*.conf" 2>/dev/null | grep -v "^\s*#")

        # ProxyRequests On/Off 구분하여 확인
        local PROXY_REQUESTS_ON=$(grep -rE "^\s*ProxyRequests\s+On" "$CONF_DIR" --include="*.conf" 2>/dev/null | grep -vi "^\s*#")
        local PROXY_REQUESTS_OFF=$(grep -rE "^\s*ProxyRequests\s+Off" "$CONF_DIR" --include="*.conf" 2>/dev/null | grep -vi "^\s*#")

        # 상세 정보 구성
        local DETAILS=""
        if [ -n "$PROXY_MODULE" ]; then
            DETAILS="[Proxy 모듈] 활성화\n$PROXY_MODULE\n"
        else
            DETAILS="[Proxy 모듈] 비활성화 (미로드)\n"
        fi

        if [ -n "$PROXY_PASS" ]; then
            DETAILS="${DETAILS}\n[ProxyPass 설정]\n$PROXY_PASS\n"
        else
            DETAILS="${DETAILS}\n[ProxyPass 설정] 없음\n"
        fi

        if [ -n "$PROXY_REQUESTS_ON" ]; then
            DETAILS="${DETAILS}\n[ProxyRequests] On (Forward Proxy 활성화 - 취약)\n$PROXY_REQUESTS_ON"
        elif [ -n "$PROXY_REQUESTS_OFF" ]; then
            DETAILS="${DETAILS}\n[ProxyRequests] Off (Forward Proxy 비활성화 - 양호)\n$PROXY_REQUESTS_OFF"
        else
            DETAILS="${DETAILS}\n[ProxyRequests] 미설정 (기본값: Off)"
        fi

        # 판정: ProxyModule 미설치 시 양호 (프록시 자체가 사용 불가)
        if [ -z "$PROXY_MODULE" ]; then
            RES="Y"
            DESC="Proxy 모듈이 로드되지 않아 프록시가 비활성화되어 양호"
            DT="$DETAILS"
        elif [ -n "$PROXY_REQUESTS_ON" ]; then
            RES="N"
            DESC="ProxyRequests On이 설정되어 Forward Proxy가 활성화되어 취약"
            DT="$DETAILS"
        elif [ -n "$PROXY_REQUESTS_OFF" ]; then
            RES="Y"
            DESC="ProxyRequests Off로 설정되어 Forward Proxy가 비활성화되어 양호"
            DT="$DETAILS"
        else
            RES="Y"  # [FIX] Apache 기본값 Off이므로 미설정 시 Y(양호) 판정
            DESC="ProxyRequests가 미설정으로 기본값 Off가 적용되어 Forward Proxy가 비활성화되어 양호"  # [FIX] 기본값 반영
            DT="$DETAILS"
        fi
    fi

    output_checkpoint "$CODE" "$CAT" "$NAME" "$IMP" "$STD" "$RES" "$DESC" "$DT"
}

check11() {
    local CODE="WEB-11"
    local CAT="서비스관리"
    local NAME="웹 서비스 경로 설정"
    local IMP="중"
    local STD="웹 서버 경로를 기타 업무와 영역이 분리된 경로로 설정 및 불필요한 경로가 존재하지 않는 경우"
    local RES=""
    local DESC=""
    local DT=""

    if [ -z "$APACHE_CONF" ] || [ ! -f "$APACHE_CONF" ]; then
        RES="N/A"
        DESC="Apache 설정 파일이 존재하지 않아 해당 없음"
        DT="APACHE_CONF: not found"
    else
        # DocumentRoot 확인 (메인 설정 + sites-enabled)
        local CONF_DIR_11=$(dirname "$APACHE_CONF")
        local DOC_ROOT=$(grep -E "^\s*DocumentRoot" "$APACHE_CONF" 2>/dev/null | head -1 | awk '{print $2}' | tr -d '"')
        # 메인 설정에 없으면 sites-enabled에서 확인
        if [ -z "$DOC_ROOT" ] && [ -d "$CONF_DIR_11/sites-enabled" ]; then
            DOC_ROOT=$(grep -rhE "^\s*DocumentRoot" "$CONF_DIR_11/sites-enabled" --include="*.conf" 2>/dev/null | grep -v "^\s*#" | head -1 | awk '{print $2}' | tr -d '"')
        fi

        # 기본 경로와 분리 여부 확인
        local DEFAULT_PATHS=("/var/www/html" "/var/www" "/usr/local/apache2/htdocs" "/srv/www/htdocs")
        local IS_DEFAULT="N"

        for path in "${DEFAULT_PATHS[@]}"; do
            if [ "$DOC_ROOT" = "$path" ]; then
                IS_DEFAULT="Y"
                break
            fi
        done

        if [ -z "$DOC_ROOT" ]; then
            RES="M"
            DESC="DocumentRoot 설정을 찾을 수 없어 수동 확인 필요"
            DT="DocumentRoot: 미설정"
        elif [ "$IS_DEFAULT" = "Y" ]; then
            RES="M"
            DESC="기본 DocumentRoot 경로가 사용되고 있어 수동 확인 필요"
            DT="DocumentRoot: $DOC_ROOT (기본 경로)"
        else
            RES="Y"
            DESC="별도의 DocumentRoot 경로가 설정되어 양호"
            DT="DocumentRoot: $DOC_ROOT"
        fi
    fi

    output_checkpoint "$CODE" "$CAT" "$NAME" "$IMP" "$STD" "$RES" "$DESC" "$DT"
}

check12() {
    local CODE="WEB-12"
    local CAT="서비스관리"
    local NAME="웹 서비스 링크 사용 금지"
    local IMP="중"
    local STD="심볼릭 링크, aliases, 바로가기 등의 링크 사용을 허용하지 않는 경우"
    local RES=""
    local DESC=""
    local DT=""

    if [ -z "$APACHE_CONF" ] || [ ! -f "$APACHE_CONF" ]; then
        RES="N/A"
        DESC="Apache 설정 파일이 존재하지 않아 해당 없음"
        DT="APACHE_CONF: not found"
    else
        local CONF_DIR=$(dirname "$APACHE_CONF")

        # FollowSymLinks 설정 확인
        local FOLLOW_LINKS=$(grep -rE "^\s*Options.*\+?FollowSymLinks" "$CONF_DIR" --include="*.conf" 2>/dev/null | grep -v "^\s*#" | grep -v "\-FollowSymLinks")

        if [ -z "$FOLLOW_LINKS" ]; then
            RES="Y"
            DESC="FollowSymLinks가 설정되지 않아 심볼릭 링크 사용이 제한되어 양호"
            DT="FollowSymLinks: 미설정 또는 -FollowSymLinks"
        else
            RES="N"
            DESC="FollowSymLinks가 설정되어 심볼릭 링크 사용이 허용되어 취약"
            DT="발견된 설정:\n$FOLLOW_LINKS"
        fi
    fi

    output_checkpoint "$CODE" "$CAT" "$NAME" "$IMP" "$STD" "$RES" "$DESC" "$DT"
}

check13() {
    local CODE="WEB-13"
    local CAT="서비스관리"
    local NAME="웹 서비스 설정 파일 노출 제한"
    local IMP="상"
    local STD="일반 사용자의 DB 연결 파일에 대한 접근을 제한하고, 불필요한 스크립트 매핑이 제거된 경우"
    local RES=""
    local DESC=""
    local DT=""

    local RES="N/A"
    local DESC="WEB-14에서 설정 파일 권한 점검으로 통합되어 해당 없음"
    local DT="Apache HTTP Server의 설정 파일 노출 제한은 WEB-14(웹 서비스 경로 내 파일의 접근 통제) 항목에서 설정 파일 권한 점검으로 통합하여 진단합니다.\n중복 점검을 방지하고 효율적인 진단을 위해 해당 항목에서 설정 파일(httpd.conf 등)의 권한을 확인합니다."

    output_checkpoint "$CODE" "$CAT" "$NAME" "$IMP" "$STD" "$RES" "$DESC" "$DT"
}

check14() {
    local CODE="WEB-14"
    local CAT="서비스관리"
    local NAME="웹 서비스 경로 내 파일의 접근 통제"
    local IMP="상"
    local STD="주요 설정 파일 및 디렉터리에 불필요한 접근 권한이 부여되지 않은 경우"
    local RES=""
    local DESC=""
    local DT=""

    if [ -z "$APACHE_CONF" ] || [ ! -f "$APACHE_CONF" ]; then
        RES="N/A"
        DESC="Apache 설정 파일이 존재하지 않아 해당 없음"
        DT="APACHE_CONF: not found"
    else
        local CONF_DIR=$(dirname "$APACHE_CONF")
        local HAS_VULN="N"
        local DETAILS=""

        # 1) 주요 설정 파일 권한 확인
        local CHECK_FILES="$APACHE_CONF"
        [ -f "$CONF_DIR/ports.conf" ] && CHECK_FILES="$CHECK_FILES $CONF_DIR/ports.conf"
        [ -f "$CONF_DIR/envvars" ] && CHECK_FILES="$CHECK_FILES $CONF_DIR/envvars"

        # sites-enabled, conf-enabled 내 설정 파일 추가
        if [ -d "$CONF_DIR/sites-enabled" ]; then
            local SITE_FILES=$(find "$CONF_DIR/sites-enabled" -name "*.conf" -type f -o -type l 2>/dev/null)
            [ -n "$SITE_FILES" ] && CHECK_FILES="$CHECK_FILES $SITE_FILES"
        fi
        if [ -d "$CONF_DIR/conf-enabled" ]; then
            local CONF_FILES=$(find "$CONF_DIR/conf-enabled" -name "*.conf" -type f -o -type l 2>/dev/null)
            [ -n "$CONF_FILES" ] && CHECK_FILES="$CHECK_FILES $CONF_FILES"
        fi

        DETAILS="[설정 파일 권한]"
        for f in $CHECK_FILES; do
            if [ -f "$f" ]; then
                local F_PERM=$(stat -c "%a" "$f" 2>/dev/null)
                local F_OWNER=$(stat -c "%U:%G" "$f" 2>/dev/null)
                local F_OTHER=${F_PERM: -1}
                if [ "$F_OTHER" -gt 0 ] 2>/dev/null; then
                    HAS_VULN="Y"
                    DETAILS="$DETAILS\n$f - 권한: $F_PERM (other 권한 제거 필요), 소유자: $F_OWNER"
                else
                    DETAILS="$DETAILS\n$f - 권한: $F_PERM, 소유자: $F_OWNER"
                fi
            fi
        done

        # 2) DocumentRoot 디렉터리 권한 확인
        local DOC_ROOT=$(grep -rhE "^\s*DocumentRoot" "$CONF_DIR" "$CONF_DIR/sites-enabled" --include="*.conf" 2>/dev/null | grep -v "^\s*#" | head -1 | awk '{print $2}' | tr -d '"')
        if [ -n "$DOC_ROOT" ] && [ -d "$DOC_ROOT" ]; then
            local DR_PERM=$(stat -c "%a" "$DOC_ROOT" 2>/dev/null)
            local DR_OWNER=$(stat -c "%U:%G" "$DOC_ROOT" 2>/dev/null)
            local DR_OTHER=${DR_PERM: -1}
            DETAILS="$DETAILS\n\n[DocumentRoot 디렉터리 권한]\n$DOC_ROOT - 권한: $DR_PERM, 소유자: $DR_OWNER"
            if [ "$DR_OTHER" -gt 5 ] 2>/dev/null; then
                HAS_VULN="Y"
                DETAILS="$DETAILS (other 쓰기 권한 제거 필요)"
            fi
        fi

        if [ "$HAS_VULN" = "Y" ]; then
            RES="N"
            DESC="설정 파일 또는 DocumentRoot에 과도한 권한이 설정되어 취약"
            DT="$DETAILS"
        else
            RES="Y"
            DESC="설정 파일 및 DocumentRoot에 적절한 권한이 설정되어 양호"
            DT="$DETAILS"
        fi
    fi

    output_checkpoint "$CODE" "$CAT" "$NAME" "$IMP" "$STD" "$RES" "$DESC" "$DT"
}

check15() {
    local CODE="WEB-15"
    local CAT="서비스관리"
    local NAME="웹 서비스의 불필요한 스크립트 매핑 제거"
    local IMP="상"
    local STD="불필요한 스크립트 매핑이 존재하지 않는 경우"
    local RES=""
    local DESC=""
    local DT=""

    local RES="N/A"
    local DESC="Apache는 모듈 기반으로 WEB-05에서 CGI를 점검하여 해당 없음"
    local DT="Apache HTTP Server는 IIS의 스크립트 매핑(.asp, .asa 등)과 달리 모듈 기반으로 스크립트를 처리합니다.\nCGI, PHP 등의 스크립트 실행은 WEB-05(지정하지 않은 CGI/ISAPI 실행 제한) 항목에서 CGI 모듈 및 ExecCGI 옵션을 점검하여 통합 진단합니다."

    output_checkpoint "$CODE" "$CAT" "$NAME" "$IMP" "$STD" "$RES" "$DESC" "$DT"
}

check16() {
    local CODE="WEB-16"
    local CAT="서비스관리"
    local NAME="웹 서비스 헤더 정보 노출 제한"
    local IMP="중"
    local STD="HTTP 응답 헤더에서 웹 서버 정보가 노출되지 않는 경우"
    local RES=""
    local DESC=""
    local DT=""

    if [ -z "$APACHE_CONF" ] || [ ! -f "$APACHE_CONF" ]; then
        RES="N/A"
        DESC="Apache 설정 파일이 존재하지 않아 해당 없음"
        DT="APACHE_CONF: not found"
    else
        local CONF_DIR=$(dirname "$APACHE_CONF")
        local SEARCH_DIRS="$CONF_DIR"
        [ -d "$CONF_DIR/mods-enabled" ] && SEARCH_DIRS="$SEARCH_DIRS $CONF_DIR/mods-enabled"
        [ -d "$CONF_DIR/sites-enabled" ] && SEARCH_DIRS="$SEARCH_DIRS $CONF_DIR/sites-enabled"
        [ -d "$CONF_DIR/conf-enabled" ] && SEARCH_DIRS="$SEARCH_DIRS $CONF_DIR/conf-enabled"

        # ServerTokens 설정 확인 (줄번호 포함)
        local SERVER_TOKENS_LINE=$(grep -rnE "^\s*ServerTokens" $SEARCH_DIRS --include="*.conf" 2>/dev/null | grep -v "^\s*#" | head -1)
        local SERVER_TOKENS=$(echo "$SERVER_TOKENS_LINE" | awk -F: '{print $NF}' | awk '{print $2}')
        local SERVER_TOKENS_FILE=$(echo "$SERVER_TOKENS_LINE" | awk -F: '{print $1}')
        local SERVER_TOKENS_LINENUM=$(echo "$SERVER_TOKENS_LINE" | awk -F: '{print $2}')

        # ServerSignature 설정 확인 (줄번호 포함)
        local SERVER_SIG_LINE=$(grep -rnE "^\s*ServerSignature" $SEARCH_DIRS --include="*.conf" 2>/dev/null | grep -v "^\s*#" | head -1)
        local SERVER_SIG=$(echo "$SERVER_SIG_LINE" | awk -F: '{print $NF}' | awk '{print $2}')
        local SERVER_SIG_FILE=$(echo "$SERVER_SIG_LINE" | awk -F: '{print $1}')
        local SERVER_SIG_LINENUM=$(echo "$SERVER_SIG_LINE" | awk -F: '{print $2}')

        local IS_SECURE="Y"
        local ISSUES=""
        local DESC_DETAIL=""

        # ServerTokens가 Prod 또는 ProductOnly가 아니면 취약
        if [ -z "$SERVER_TOKENS" ] || [[ ! "${SERVER_TOKENS,,}" =~ ^(prod|productonly)$ ]]; then
            IS_SECURE="N"
            local TOKEN_UPPER=$(echo "$SERVER_TOKENS" | tr '[:lower:]' '[:upper:]')
            case "$TOKEN_UPPER" in
                FULL)    DESC_DETAIL="ServerTokens Full이 설정되어 웹 서버의 모든 정보(버전, OS, 모듈)가 노출되어 취약" ;;
                OS)      DESC_DETAIL="ServerTokens OS가 설정되어 웹 서버 버전 및 운영체제 정보가 노출되어 취약" ;;
                MINOR|MINIMAL|MAJOR)  DESC_DETAIL="ServerTokens가 Prod 이외 값으로 설정되어 웹 서버 버전 정보가 노출되어 취약" ;;
                *)       DESC_DETAIL="ServerTokens가 미설정되어 기본 정보가 노출되어 취약" ;;
            esac
            ISSUES="ServerTokens: ${SERVER_TOKENS:-미설정} (Prod 권장)"
            [ -n "$SERVER_TOKENS_FILE" ] && ISSUES="$ISSUES\n  설정파일: $SERVER_TOKENS_FILE:$SERVER_TOKENS_LINENUM"
        fi

        # ServerSignature가 Off가 아니면 취약
        if [ -z "$SERVER_SIG" ] || [[ "${SERVER_SIG,,}" != "off" ]]; then
            IS_SECURE="N"
            if [ -n "$DESC_DETAIL" ]; then
                DESC_DETAIL="${DESC_DETAIL}, ServerSignature가 Off가 아니어서 취약"
            else
                DESC_DETAIL="ServerSignature가 Off가 아니어서 서버 정보가 노출되어 취약"
            fi
            ISSUES="${ISSUES:+$ISSUES\n}ServerSignature: ${SERVER_SIG:-미설정} (Off 권장)"
            [ -n "$SERVER_SIG_FILE" ] && ISSUES="$ISSUES\n  설정파일: $SERVER_SIG_FILE:$SERVER_SIG_LINENUM"
        fi

        if [ "$IS_SECURE" = "Y" ]; then
            RES="Y"
            DESC="ServerTokens Prod 및 ServerSignature Off로 설정되어 서버 정보 노출이 제한되어 양호"
            DT="ServerTokens: $SERVER_TOKENS"
            [ -n "$SERVER_TOKENS_FILE" ] && DT="$DT\n  설정파일: $SERVER_TOKENS_FILE:$SERVER_TOKENS_LINENUM"
            DT="$DT\nServerSignature: $SERVER_SIG"
            [ -n "$SERVER_SIG_FILE" ] && DT="$DT\n  설정파일: $SERVER_SIG_FILE:$SERVER_SIG_LINENUM"
        else
            RES="N"
            DESC="$DESC_DETAIL"
            DT="$ISSUES"
        fi
    fi

    output_checkpoint "$CODE" "$CAT" "$NAME" "$IMP" "$STD" "$RES" "$DESC" "$DT"
}

check17() {
    local CODE="WEB-17"
    local CAT="서비스관리"
    local NAME="웹 서비스 가상 디렉로리 삭제"
    local IMP="중"
    local STD="불필요한 가상 디렉터리가 존재하지 않는 경우"
    local RES=""
    local DESC=""
    local DT=""

    if [ -z "$APACHE_CONF" ] || [ ! -f "$APACHE_CONF" ]; then
        RES="N/A"
        DESC="Apache 설정 파일이 존재하지 않아 해당 없음"
        DT="APACHE_CONF: not found"
    else
        local CONF_DIR=$(dirname "$APACHE_CONF")

        # Alias 설정 확인
        local ALIASES=$(grep -rE "^\s*Alias\s+" "$CONF_DIR" --include="*.conf" 2>/dev/null | grep -v "^\s*#")

        if [ -z "$ALIASES" ]; then
            RES="Y"
            DESC="불필요한 Alias 설정이 존재하지 않아 양호"
            DT="Alias: 미설정"
        else
            RES="M"
            DESC="Alias 설정이 존재하여 수동 확인 필요"
            DT="Alias 설정:\n$ALIASES"
        fi
    fi

    output_checkpoint "$CODE" "$CAT" "$NAME" "$IMP" "$STD" "$RES" "$DESC" "$DT"
}

check18() {
    local CODE="WEB-18"
    local CAT="서비스관리"
    local NAME="웹 서비스 WebDAV 비활성화"
    local IMP="상"
    local STD="WebDAV 서비스를 비활성화하고 있는 경우"
    local RES=""
    local DESC=""
    local DT=""

    if [ -z "$APACHE_CONF" ] || [ ! -f "$APACHE_CONF" ]; then
        RES="N/A"
        DESC="Apache 설정 파일이 존재하지 않아 해당 없음"
        DT="APACHE_CONF: not found"
    else
        local CONF_DIR=$(dirname "$APACHE_CONF")
        local SEARCH_DIRS="$CONF_DIR"
        [ -d "$CONF_DIR/sites-enabled" ] && SEARCH_DIRS="$SEARCH_DIRS $CONF_DIR/sites-enabled"
        [ -d "$CONF_DIR/conf-enabled" ] && SEARCH_DIRS="$SEARCH_DIRS $CONF_DIR/conf-enabled"

        # WebDAV 모듈 확인 (conf 파일 + mods-enabled 심볼릭 링크)
        local DAV_MODULE=$(grep -rnE "^\s*LoadModule.*(dav_module|dav_fs_module)" $SEARCH_DIRS --include="*.conf" 2>/dev/null | grep -v "^\s*#")

        # mods-enabled 내 dav 모듈 로드 여부 확인 (Ubuntu/Debian 방식)
        local DAV_MOD_ENABLED=""
        if [ -d "$CONF_DIR/mods-enabled" ]; then
            DAV_MOD_ENABLED=$(ls -la "$CONF_DIR/mods-enabled/" 2>/dev/null | grep -E "dav.*\.load")
        fi

        # Dav On 설정 확인
        local DAV_ON=$(grep -rnE "^\s*Dav\s+On" $SEARCH_DIRS --include="*.conf" 2>/dev/null | grep -v "^\s*#")

        if [ -z "$DAV_MODULE" ] && [ -z "$DAV_MOD_ENABLED" ] && [ -z "$DAV_ON" ]; then
            RES="Y"
            DESC="WebDAV 모듈이 로드되지 않아 비활성화되어 양호"
            DT="WebDAV 모듈: 미로드\nmods-enabled: dav 모듈 없음\nDav On: 미설정"
        # [FIX] Dav On 설정이 있을 때만 N 판정 — 모듈만 로드는 실질적 동작 안 함
        elif [ -n "$DAV_ON" ]; then
            RES="N"
            DESC="Dav On이 설정되어 WebDAV가 활성화되어 취약"
            local DETAILS=""
            [ -n "$DAV_MODULE" ] && DETAILS="WebDAV 모듈 (conf):\n$DAV_MODULE\n"
            [ -n "$DAV_MOD_ENABLED" ] && DETAILS="${DETAILS}WebDAV 모듈 (mods-enabled):\n$DAV_MOD_ENABLED\n"
            DETAILS="${DETAILS}Dav On:\n$DAV_ON"
            DT="$DETAILS"
        else
            # [FIX] 모듈만 로드 + Dav On 없음 → Y (양호)
            RES="Y"
            DESC="WebDAV 모듈이 로드되어 있으나 Dav On이 미설정되어 비활성 상태이므로 양호"
            local DETAILS=""
            [ -n "$DAV_MODULE" ] && DETAILS="WebDAV 모듈 (conf):\n$DAV_MODULE\n"
            [ -n "$DAV_MOD_ENABLED" ] && DETAILS="${DETAILS}WebDAV 모듈 (mods-enabled):\n$DAV_MOD_ENABLED\n"
            DETAILS="${DETAILS}Dav On: 미설정"
            DT="$DETAILS"
        fi
    fi

    output_checkpoint "$CODE" "$CAT" "$NAME" "$IMP" "$STD" "$RES" "$DESC" "$DT"
}

check19() {
    local CODE="WEB-19"
    local CAT="보안설정"
    local NAME="웹 서비스 SSI(Server Side Includes) 사용 제한"
    local IMP="중"
    local STD="웹 서비스 SSI 사용 설정이 비활성화되어 있는 경우"
    local RES=""
    local DESC=""
    local DT=""

    if [ -z "$APACHE_CONF" ] || [ ! -f "$APACHE_CONF" ]; then
        RES="N/A"
        DESC="Apache 설정 파일이 존재하지 않아 해당 없음"
        DT="APACHE_CONF: not found"
    else
        local CONF_DIR=$(dirname "$APACHE_CONF")

        # SSI 모듈 확인
        local SSI_MODULE=$(grep -rE "^\s*LoadModule.*include_module" "$CONF_DIR" --include="*.conf" 2>/dev/null | grep -v "^\s*#")

        # Options Includes 설정 확인
        local INCLUDES=$(grep -rE "^\s*Options.*\+?Includes" "$CONF_DIR" --include="*.conf" 2>/dev/null | grep -v "^\s*#" | grep -v "\-Includes")

        if [ -z "$SSI_MODULE" ] && [ -z "$INCLUDES" ]; then
            RES="Y"
            DESC="SSI 모듈 및 Options Includes가 설정되지 않아 SSI가 비활성화되어 양호"
            DT="SSI 모듈: 비활성화\nOptions Includes: 미설정"
        else
            RES="N"
            DESC="SSI 모듈 또는 Options Includes가 설정되어 SSI가 활성화되어 취약"
            local DETAILS=""
            [ -n "$SSI_MODULE" ] && DETAILS="SSI 모듈:\n$SSI_MODULE\n"
            [ -n "$INCLUDES" ] && DETAILS="${DETAILS}Options Includes:\n$INCLUDES"
            DT="$DETAILS"
        fi
    fi

    output_checkpoint "$CODE" "$CAT" "$NAME" "$IMP" "$STD" "$RES" "$DESC" "$DT"
}

check20() {
    local CODE="WEB-20"
    local CAT="보안설정"
    local NAME="SSL/TLS 활성화"
    local IMP="상"
    local STD="SSL/TLS 설정이 활성화되어 있는 경우"
    local RES=""
    local DESC=""
    local DT=""

    # [FIX] APACHE_CONF 없는 경우 N/A 분기 추가 (기존 누락)
    if [ -z "$APACHE_CONF" ] || [ ! -f "$APACHE_CONF" ]; then
        RES="N/A"
        DESC="Apache 설정 파일이 존재하지 않아 해당 없음"
        DT="APACHE_CONF: not found"
    else
        local CONF_DIR=$(dirname "$APACHE_CONF")

        # [FIX] httpd -M / apache2ctl -M 런타임 체크 → 설정파일 LoadModule 확인으로 변경
        local SSL_MODULE=$(grep -rE "^\s*LoadModule\s+ssl_module" "$CONF_DIR" --include="*.conf" 2>/dev/null | grep -v "^\s*#")
        # [FIX] mods-enabled 심볼릭 링크도 확인 (Debian/Ubuntu 방식)
        if [ -z "$SSL_MODULE" ] && [ -d "$CONF_DIR/mods-enabled" ]; then
            SSL_MODULE=$(ls -la "$CONF_DIR/mods-enabled/" 2>/dev/null | grep -E "ssl\.load")
        fi

        # SSL 설정 확인 (SSLEngine on/off 구분)
        local SSL_ENGINE_ON=""
        local SSL_ENGINE_OFF=""
        local LISTEN_443=""

        # SSLEngine on 설정 확인 (대소문자 구분 없이)
        SSL_ENGINE_ON=$(grep -rE "^\s*SSLEngine\s+[Oo][Nn]" "$CONF_DIR" --include="*.conf" 2>/dev/null | grep -v "^\s*#")
        # SSLEngine off 설정 확인 (대소문자 구분 없이)
        SSL_ENGINE_OFF=$(grep -rE "^\s*SSLEngine\s+[Oo][Ff][Ff]" "$CONF_DIR" --include="*.conf" 2>/dev/null | grep -v "^\s*#")
        # 443 포트 Listen 확인
        LISTEN_443=$(grep -rE "^\s*Listen.*443" "$CONF_DIR" --include="*.conf" 2>/dev/null | grep -v "^\s*#")

        # 상세 정보 구성 (항상 모든 설정값 출력)
        local DETAILS=""
        if [ -n "$SSL_MODULE" ]; then
            DETAILS="[SSL 모듈] 로드됨\n$SSL_MODULE\n"
        else
            DETAILS="[SSL 모듈] 미로드\n"
        fi

        if [ -n "$SSL_ENGINE_ON" ]; then
            DETAILS="${DETAILS}\n[SSLEngine] On\n$SSL_ENGINE_ON\n"
        elif [ -n "$SSL_ENGINE_OFF" ]; then
            DETAILS="${DETAILS}\n[SSLEngine] Off\n$SSL_ENGINE_OFF\n"
        else
            DETAILS="${DETAILS}\n[SSLEngine] 미설정\n"
        fi

        if [ -n "$LISTEN_443" ]; then
            DETAILS="${DETAILS}\n[Listen 443]\n$LISTEN_443"
        else
            DETAILS="${DETAILS}\n[Listen 443] 미설정"
        fi

        # 판정 로직
        if [ -n "$SSL_MODULE" ] && [ -n "$SSL_ENGINE_ON" ]; then
            RES="Y"
            DESC="SSLEngine On이 설정되어 SSL/TLS가 활성화되어 양호"
            DT="$DETAILS"
        elif [ -n "$SSL_MODULE" ] && [ -n "$SSL_ENGINE_OFF" ] && [ -z "$SSL_ENGINE_ON" ]; then
            RES="N"
            DESC="SSL 모듈은 로드되었으나 SSLEngine이 Off로 설정되어 취약"
            DT="$DETAILS"
        elif [ -n "$SSL_MODULE" ]; then
            RES="M"
            DESC="SSL 모듈은 로드되었으나 SSLEngine 설정이 미확인되어 수동 확인 필요"
            DT="$DETAILS"
        elif [ -n "$SSL_ENGINE_ON" ]; then
            # SSL 모듈 미로드 + SSLEngine On 설정 존재
            RES="M"
            DESC="SSLEngine On 설정이 있으나 SSL 모듈이 로드되지 않아 수동 확인 필요"
            DT="$DETAILS\n\n[주의] SSL 모듈을 로드해야 SSL/TLS가 작동합니다."
        else
            RES="N"
            DESC="SSL/TLS가 비활성화되어 취약"
            DT="$DETAILS"
        fi
    fi

    output_checkpoint "$CODE" "$CAT" "$NAME" "$IMP" "$STD" "$RES" "$DESC" "$DT"
}

check21() {
    local CODE="WEB-21"
    local CAT="보안설정"
    local NAME="HTTP 리디렉션"
    local IMP="중"
    local STD="HTTP 접근 시 HTTPS Redirection이 활성화된 경우"
    local RES=""
    local DESC=""
    local DT=""

    if [ -z "$APACHE_CONF" ] || [ ! -f "$APACHE_CONF" ]; then
        RES="N/A"
        DESC="Apache 설정 파일이 존재하지 않아 해당 없음"
        DT="APACHE_CONF: not found"
    else
        local CONF_DIR=$(dirname "$APACHE_CONF")

        # HTTP to HTTPS 리디렉션 설정 확인
        # [FIX] Redirect 패턴 구체화: permanent/301 또는 "/" 경로로 https:// 리디렉션만 매칭
        local REDIRECT=$(grep -rE "^\s*Redirect\s+(permanent|301)\s+.*https://|^\s*Redirect\s+/\s+https://" "$CONF_DIR" --include="*.conf" 2>/dev/null | grep -v "^\s*#")

        # RewriteEngine On/Off 확인 (RewriteRule이 동작하려면 On 필수)
        local REWRITE_ENGINE_ON=$(grep -rE "^\s*RewriteEngine\s+[Oo][Nn]" "$CONF_DIR" --include="*.conf" 2>/dev/null | grep -v "^\s*#")
        local REWRITE_ENGINE_OFF=$(grep -rE "^\s*RewriteEngine\s+[Oo][Ff][Ff]" "$CONF_DIR" --include="*.conf" 2>/dev/null | grep -v "^\s*#")

        # RewriteRule로 HTTPS 리디렉션 설정 확인
        local REWRITE_RULE=$(grep -rE "^\s*RewriteRule.*https" "$CONF_DIR" --include="*.conf" 2>/dev/null | grep -v "^\s*#")

        # RewriteCond로 HTTPS 조건 확인
        local REWRITE_COND=$(grep -rE "^\s*RewriteCond.*HTTPS.*off" "$CONF_DIR" --include="*.conf" 2>/dev/null | grep -v "^\s*#")

        local DETAILS=""
        [ -n "$REDIRECT" ] && DETAILS="[Redirect 설정]\n$REDIRECT\n"
        if [ -n "$REWRITE_ENGINE_ON" ]; then
            DETAILS="${DETAILS}\n[RewriteEngine] On\n$REWRITE_ENGINE_ON\n"
        elif [ -n "$REWRITE_ENGINE_OFF" ]; then
            DETAILS="${DETAILS}\n[RewriteEngine] Off (비활성화)\n$REWRITE_ENGINE_OFF\n"
        else
            DETAILS="${DETAILS}\n[RewriteEngine] 미설정\n"
        fi
        [ -n "$REWRITE_RULE" ] && DETAILS="${DETAILS}\n[RewriteRule]\n$REWRITE_RULE\n"
        [ -n "$REWRITE_COND" ] && DETAILS="${DETAILS}\n[RewriteCond]\n$REWRITE_COND"

        if [ -n "$REDIRECT" ]; then
            # Redirect 디렉티브 사용 시 양호
            RES="Y"
            DESC="Redirect 디렉티브로 HTTP to HTTPS 리디렉션이 설정되어 양호"
            DT="$DETAILS"
        elif [ -n "$REWRITE_RULE" ] && [ -n "$REWRITE_ENGINE_ON" ]; then
            # [FIX] RewriteEngine On이 하나라도 있으면 Y 처리 (Off 동시 존재 무시)
            RES="Y"
            DESC="mod_rewrite로 HTTP to HTTPS 리디렉션이 설정되어 양호"
            DT="$DETAILS"
        elif [ -n "$REWRITE_RULE" ] && [ -z "$REWRITE_ENGINE_ON" ]; then
            # RewriteRule은 있지만 RewriteEngine On이 없으면 취약
            RES="N"
            DESC="RewriteRule이 있으나 RewriteEngine On이 설정되지 않아 리디렉션이 동작하지 않아 취약"
            DT="$DETAILS\n\n[경고] RewriteEngine On이 설정되지 않아 RewriteRule이 동작하지 않습니다."
        else
            RES="N"
            DESC="HTTP to HTTPS 리디렉션이 설정되지 않아 취약"
            DT="[Redirect] 미설정\n[RewriteRule] 미설정"
        fi
    fi

    output_checkpoint "$CODE" "$CAT" "$NAME" "$IMP" "$STD" "$RES" "$DESC" "$DT"
}

check22() {
    local CODE="WEB-22"
    local CAT="보안설정"
    local NAME="에러 페이지 관리"
    local IMP="하"
    local STD="웹 서비스 에러 페이지가 별도로 지정된 경우"
    local RES=""
    local DESC=""
    local DT=""

    if [ -z "$APACHE_CONF" ] || [ ! -f "$APACHE_CONF" ]; then
        RES="N/A"
        DESC="Apache 설정 파일이 존재하지 않아 해당 없음"
        DT="APACHE_CONF: not found"
    else
        local CONF_DIR=$(dirname "$APACHE_CONF")
        local SEARCH_DIRS="$CONF_DIR"
        [ -d "$CONF_DIR/sites-enabled" ] && SEARCH_DIRS="$SEARCH_DIRS $CONF_DIR/sites-enabled"
        [ -d "$CONF_DIR/conf-enabled" ] && SEARCH_DIRS="$SEARCH_DIRS $CONF_DIR/conf-enabled"

        # ErrorDocument 설정 확인 (줄번호 포함)
        local ERROR_DOC=$(grep -rnE "^\s*ErrorDocument" $SEARCH_DIRS --include="*.conf" 2>/dev/null | grep -v "^\s*#")

        if [ -n "$ERROR_DOC" ]; then
            # [FIX] 필수 에러 코드를 403, 404, 500으로 축소 (KISA 기준에 맞춤)
            local REQUIRED_CODES="403 404 500"  # [FIX] 400, 401 제거
            local MISSING_CODES=""
            for code in $REQUIRED_CODES; do
                if ! echo "$ERROR_DOC" | grep -qE "ErrorDocument\s+$code\b"; then
                    MISSING_CODES="$MISSING_CODES $code"
                fi
            done

            if [ -z "$MISSING_CODES" ]; then
                RES="Y"
                DESC="주요 에러 코드(403,404,500)에 대한 ErrorDocument가 설정되어 양호"  # [FIX]
                DT="ErrorDocument 설정:\n$ERROR_DOC"
            else
                RES="N"
                DESC="주요 에러 코드 중 일부에 대한 ErrorDocument가 설정되지 않아 취약"
                DT="ErrorDocument 설정:\n$ERROR_DOC\n\n[취약] 미설정 에러 코드:$MISSING_CODES\n필수 에러 코드(403,404,500)에 대한 ErrorDocument 설정이 필요합니다."  # [FIX]
            fi
        else
            RES="N"
            DESC="ErrorDocument가 설정되지 않아 기본 에러 페이지가 사용되어 취약"
            DT="ErrorDocument: 미설정 (기본 에러 페이지 사용)\n\n[취약] 필수 에러 코드(403,404,500)에 대한 ErrorDocument 설정이 필요합니다."  # [FIX]
        fi
    fi

    output_checkpoint "$CODE" "$CAT" "$NAME" "$IMP" "$STD" "$RES" "$DESC" "$DT"
}

check23() {
    local CODE="WEB-23"
    local CAT="보안설정"
    local NAME="LDAP 알고리즘 적절하게 구성"
    local IMP="중"
    local STD="LDAP 연결 인증 시 안전한 비밀번호 다이제스트 알고리즘을 사용하는 경우"
    local RES=""
    local DESC=""
    local DT=""

    local RES="N/A"
    local DESC="Apache는 LDAP 인증 서버가 아니어서 해당 없음"
    local DT="Apache HTTP Server는 LDAP 인증 서버가 아니며, LDAP 연동 시 mod_ldap/mod_authnz_ldap 모듈을 사용합니다.\nLDAP 인증 알고리즘 및 보안 설정은 연동된 LDAP 서버(OpenLDAP, Active Directory 등)에서 관리하며, Apache는 클라이언트 역할만 수행합니다."

    output_checkpoint "$CODE" "$CAT" "$NAME" "$IMP" "$STD" "$RES" "$DESC" "$DT"
}

check24() {
    local CODE="WEB-24"
    local CAT="보안설정"
    local NAME="별도의 업로드 경로 사용 및 권한 설정"
    local IMP="중"
    local STD="별도의 업로드 경로를 사용하고 일반 사용자의 접근 권한이 부여되지 않은 경우"
    local RES=""
    local DESC=""
    local DT=""

    # 일반적인 업로드 디렉터리 확인
    local UPLOAD_PATHS=(
        "/var/www/html/uploads"
        "/var/www/uploads"
        "/srv/www/uploads"
    )

    local FOUND_UPLOAD=""
    local UPLOAD_PERMS=""

    for path in "${UPLOAD_PATHS[@]}"; do
        if [ -d "$path" ]; then
            local PERM=$(stat -c "%a" "$path" 2>/dev/null)
            local OWNER=$(stat -c "%U:%G" "$path" 2>/dev/null)
            FOUND_UPLOAD="$path"
            UPLOAD_PERMS="$path - 권한: $PERM, 소유자: $OWNER"
            break
        fi
    done

    if [ -z "$FOUND_UPLOAD" ]; then
        RES="M"
        DESC="업로드 디렉터리를 찾을 수 없어 수동 확인 필요"
        DT="일반적인 경로에 업로드 디렉터리 없음"
    else
        local PERM=$(stat -c "%a" "$FOUND_UPLOAD" 2>/dev/null)
        local OTHER_PERM=${PERM: -1}

        if [ "$OTHER_PERM" -eq 0 ]; then
            RES="Y"
            DESC="업로드 디렉터리에 other 권한이 없어 적절하게 설정되어 양호"
            DT="$UPLOAD_PERMS"
        else
            RES="N"
            DESC="업로드 디렉터리에 other 접근 권한이 존재하여 취약"
            DT="$UPLOAD_PERMS (other 권한 제거 필요)"
        fi
    fi

    output_checkpoint "$CODE" "$CAT" "$NAME" "$IMP" "$STD" "$RES" "$DESC" "$DT"
}

check25() {
    local CODE="WEB-25"
    local CAT="패치및로그관리"
    local NAME="주기적 보안 패치 및 벤더 권고사항 적용"
    local IMP="상"
    local STD="최신 보안 패치가 적용되어 있으며, 패치 적용 정책을 수립하여 주기적인 패치 관리를 하는 경우"
    local RES=""
    local DESC=""
    local DT=""

    # Apache 버전 확인
    local VERSION=""
    if command -v httpd &>/dev/null; then
        VERSION=$(httpd -v 2>/dev/null | head -1)
    elif command -v apache2 &>/dev/null; then
        VERSION=$(apache2 -v 2>/dev/null | head -1)
    fi

    if [ -z "$VERSION" ]; then
        RES="N/A"
        DESC="Apache 버전을 확인할 수 없어 해당 없음"
        DT="httpd/apache2 명령어를 찾을 수 없음"
    else
        RES="M"
        DESC="Apache 버전 정보 확인됨, 수동 확인 필요"
        DT="$VERSION\n\n최신 버전 확인: https://httpd.apache.org/download.cgi"
    fi

    output_checkpoint "$CODE" "$CAT" "$NAME" "$IMP" "$STD" "$RES" "$DESC" "$DT"
}

check26() {
    local CODE="WEB-26"
    local CAT="패치및로그관리"
    local NAME="로그 디렉터리 및 파일 권한 설정"
    local IMP="중"
    local STD="로그 디렉터리 및 파일에 일반 사용자의 접근 권한이 없는 경우"
    local RES=""
    local DESC=""
    local DT=""

    # 로그 디렉터리 찾기
    local LOG_DIRS=(
        "/var/log/httpd"
        "/var/log/apache2"
        "/usr/local/apache2/logs"
    )

    local FOUND_LOG=""
    for path in "${LOG_DIRS[@]}"; do
        if [ -d "$path" ]; then
            FOUND_LOG="$path"
            break
        fi
    done

    if [ -z "$FOUND_LOG" ]; then
        RES="M"
        DESC="로그 디렉터리를 찾을 수 없어 수동 확인 필요"
        DT="일반적인 경로에 로그 디렉터리 없음"
    else
        local DIR_PERM=$(stat -c "%a" "$FOUND_LOG" 2>/dev/null)
        local DIR_OWNER=$(stat -c "%U:%G" "$FOUND_LOG" 2>/dev/null)
        local OTHER_PERM=${DIR_PERM: -1}

        # 로그 파일 권한 확인
        # [FIX] *.log 외에 *_log 패턴도 포함 (Rocky/RHEL: access_log, error_log)
        local LOG_FILES=$(find "$FOUND_LOG" -type f \( -name "*.log" -o -name "*_log" \) 2>/dev/null | head -5)
        local FILE_PERMS=""
        for f in $LOG_FILES; do
            local F_PERM=$(stat -c "%a %n" "$f" 2>/dev/null)
            FILE_PERMS="$FILE_PERMS\n$F_PERM"
        done

        if [ "$OTHER_PERM" -eq 0 ]; then
            RES="Y"
            DESC="로그 디렉터리에 other 권한이 없어 적절하게 설정되어 양호"
            DT="$FOUND_LOG - 권한: $DIR_PERM, 소유자: $DIR_OWNER\n로그 파일:$FILE_PERMS"
        else
            RES="N"
            DESC="로그 디렉터리에 other 접근 권한이 존재하여 취약"
            DT="$FOUND_LOG - 권한: $DIR_PERM (other 권한 제거 필요)\n소유자: $DIR_OWNER\n로그 파일:$FILE_PERMS"
        fi
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
echo "  OS: $SYS_OS_FN"
echo "  서비스: ${SVC_VERSION:-Not found}"
echo "  설정: ${SVC_CONF:-Not found}"
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
            <n>$SYS_OS_NAME</n>
            <fn>$SYS_OS_FN</fn>
        </os>
        <kn>$SYS_KN</kn>
        <arch>$SYS_ARCH</arch>
        <net>
            <ip>$SYS_IP</ip>
            <all><![CDATA[$SYS_NET_ALL]]></all>
        </net>
        <svc>
            <ver><![CDATA[${SVC_VERSION:-N/A}]]></ver>
            <conf>${SVC_CONF:-N/A}</conf>
        </svc>
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
