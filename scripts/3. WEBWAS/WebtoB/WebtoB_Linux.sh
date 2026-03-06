#!/bin/bash
#================================================================
# WebtoB_Linux 보안 진단 스크립트
# KISA 주요정보통신기반시설 기술적 취약점 분석·평가 기준
#================================================================
# 버전  : 2603070
# 대상  : WebtoB_Linux
# 항목  : WEB-01 ~ WEB-26 (26개)
# 제작  : Seedgen
#================================================================
META_STD="KISA"

# WebtoB 설치 경로 (자동 탐지 실패 시 수동 설정)
WEBTOB_HOME=""
WEBTOB_CONF=""

#================================================================
# INIT
#================================================================
META_VER="1.0"
META_PLAT="WebtoB"
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
# WebtoB 설치 경로 자동 탐지
detect_webtob() {
    # WEBTOBDIR 환경변수 확인
    if [ -n "$WEBTOBDIR" ] && [ -d "$WEBTOBDIR" ]; then
        WEBTOB_HOME="$WEBTOBDIR"
    fi

    # 일반적인 경로에서 찾기
    if [ -z "$WEBTOB_HOME" ]; then
        local COMMON_PATHS=(
            "/home/tmax/webtob"
            "/home/webtob/webtob"
            "/opt/webtob"
            "/usr/local/webtob"
            "/sw/webtob"
            "/sw/webtob5"
            "/root/webtob"
            "/webtob"
        )
        for path in "${COMMON_PATHS[@]}"; do
            if [ -d "$path" ]; then
                WEBTOB_HOME="$path"
                break
            fi
        done
    fi

    # http.m 설정 파일 찾기
    if [ -n "$WEBTOB_HOME" ]; then
        if [ -f "$WEBTOB_HOME/config/http.m" ]; then
            WEBTOB_CONF="$WEBTOB_HOME/config/http.m"
        elif [ -f "$WEBTOB_HOME/conf/http.m" ]; then
            WEBTOB_CONF="$WEBTOB_HOME/conf/http.m"
        fi
    fi

    # 프로세스에서 경로 추출
    if [ -z "$WEBTOB_HOME" ]; then
        local WS_PID=$(pgrep -f "wsm" 2>/dev/null | head -1)
        if [ -n "$WS_PID" ]; then
            local WS_PATH=$(readlink -f /proc/$WS_PID/exe 2>/dev/null)
            if [ -n "$WS_PATH" ]; then
                WEBTOB_HOME=$(dirname $(dirname "$WS_PATH"))
                if [ -f "$WEBTOB_HOME/config/http.m" ]; then
                    WEBTOB_CONF="$WEBTOB_HOME/config/http.m"
                fi
            fi
        fi
    fi
}

# WebtoB 탐지 실행
detect_webtob

# http.m 섹션 파싱 공통 함수
# 특정 섹션(*ALIAS, *VHOST, *REVERSE_PROXY 등) 내용 추출
get_section() {
    local SECTION_NAME="$1"
    local CONF_FILE="${2:-$WEBTOB_CONF}"

    if [ -z "$CONF_FILE" ] || [ ! -f "$CONF_FILE" ]; then
        return 1
    fi

    # 섹션 시작(*SECTION_NAME)부터 다음 섹션(*로 시작) 전까지 추출
    # 첫 줄(섹션 헤더)과 마지막 줄(다음 섹션 헤더) 제외, 주석과 빈 줄 제외
    sed -n "/^\*${SECTION_NAME}/,/^\*[A-Z]/p" "$CONF_FILE" 2>/dev/null | \
        sed '1d;$d' | \
        grep -v "^\s*#" | \
        grep -v "^$"
}

# WebtoB 버전 정보
WEBTOB_VERSION=""
if command -v wscfl &>/dev/null; then
    WEBTOB_VERSION=$(wscfl -version 2>/dev/null | head -1)
elif [ -n "$WEBTOB_HOME" ] && [ -x "$WEBTOB_HOME/bin/wscfl" ]; then
    WEBTOB_VERSION=$("$WEBTOB_HOME/bin/wscfl" -version 2>/dev/null | head -1)
fi

SVC_VERSION="$WEBTOB_VERSION"
SVC_CONF="$WEBTOB_CONF"

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
    local DESC="WebtoB는 별도의 관리자 계정이 없음 (설정 파일 기반 운영)"
    local DT="WebtoB는 Apache, IIS와 달리 별도의 관리 콘솔이나 관리자 계정을 사용하지 않습니다.\n설정 파일(http.m)을 직접 편집하여 운영하므로 해당 항목은 적용 대상이 아닙니다."

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
    local DESC="WebtoB는 별도의 내장 인증 계정이 없음"
    local DT="WebtoB는 웹 서버 자체에 내장된 인증 계정 시스템이 없습니다.\n인증이 필요한 경우 OS 계정 또는 별도의 인증 모듈을 사용하므로 해당 항목은 적용 대상이 아닙니다."

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
    local DESC="WebtoB는 별도의 비밀번호 파일이 없음"
    local DT="WebtoB는 Apache의 .htpasswd와 같은 별도의 비밀번호 파일을 사용하지 않습니다.\n인증이 필요한 경우 외부 인증 모듈이나 WAS 연동을 통해 처리하므로 해당 항목은 적용 대상이 아닙니다."

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

    if [ -z "$WEBTOB_CONF" ] || [ ! -f "$WEBTOB_CONF" ]; then
        RES="N/A"
        DESC="WebtoB 설정 파일을 찾을 수 없음"
        DT="WEBTOB_CONF: not found"
    else
        # *NODE 절에서 Options 설정 확인
        local OPTIONS_INDEXES=$(grep -E "^\s*Options\s*=" "$WEBTOB_CONF" 2>/dev/null | grep -v "^\s*#")
        local INDEXES_ON=$(echo "$OPTIONS_INDEXES" | grep -v "\-Indexes" | grep -i "Indexes")

        if [ -z "$OPTIONS_INDEXES" ]; then
            RES="Y"
            DESC="Options 지시자가 설정되지 않음 (디렉터리 리스팅 비활성화)"
            DT="Options: 미설정 (기본값: 비활성화)"
        elif [ -z "$INDEXES_ON" ]; then
            RES="Y"
            DESC="디렉터리 리스팅이 비활성화되어 있음"
            DT="Options 설정:\n$OPTIONS_INDEXES"
        else
            RES="N"
            DESC="디렉터리 리스팅이 활성화되어 있음"
            DT="발견된 설정:\n$INDEXES_ON\n\n권장: Options = \"-Indexes\""
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

    if [ -z "$WEBTOB_CONF" ] || [ ! -f "$WEBTOB_CONF" ]; then
        RES="N/A"
        DESC="WebtoB 설정 파일을 찾을 수 없음"
        DT="WEBTOB_CONF: not found"
    else
        # *SVRGROUP, *SERVER, *URI 절에서 CGI 설정 확인
        local CGI_SVRGROUP=$(grep -E "^\s*\w+.*SVRTYPE\s*=\s*CGI" "$WEBTOB_CONF" 2>/dev/null | grep -v "^\s*#")
        local CGI_URI=$(grep -E "^\s*\w+.*Svrtype\s*=\s*CGI" "$WEBTOB_CONF" 2>/dev/null | grep -v "^\s*#")

        local DETAILS=""
        [ -n "$CGI_SVRGROUP" ] && DETAILS="CGI SVRGROUP:\n$CGI_SVRGROUP\n"
        [ -n "$CGI_URI" ] && DETAILS="${DETAILS}CGI URI:\n$CGI_URI"

        if [ -z "$CGI_SVRGROUP" ] && [ -z "$CGI_URI" ]; then
            RES="Y"
            DESC="CGI 실행이 제한되어 있음"
            DT="CGI SVRTYPE: 미설정\nCGI URI: 미설정"
        else
            RES="M"
            DESC="CGI 설정 존재 (수동 확인 필요)"
            DT="$DETAILS\n\n불필요한 CGI 설정은 주석 처리 권장"
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

    if [ -z "$WEBTOB_CONF" ] || [ ! -f "$WEBTOB_CONF" ]; then
        RES="N/A"
        DESC="WebtoB 설정 파일을 찾을 수 없음"
        DT="WEBTOB_CONF: not found"
    else
        # UpperDirRestrict 설정 확인
        local UPPER_DIR=$(grep -E "^\s*UpperDirRestrict" "$WEBTOB_CONF" 2>/dev/null | grep -v "^\s*#")

        if [ -z "$UPPER_DIR" ]; then
            RES="M"
            DESC="UpperDirRestrict 설정이 없음 (수동 확인 필요)"
            DT="UpperDirRestrict: 미설정\n\n권장: UpperDirRestrict = N"
        elif echo "$UPPER_DIR" | grep -qiE "=\s*N"; then
            RES="Y"
            DESC="상위 디렉터리 접근이 제한되어 있음"
            DT="$UPPER_DIR"
        else
            RES="N"
            DESC="상위 디렉터리 접근이 허용되어 있음"
            DT="$UPPER_DIR\n\n권장: UpperDirRestrict = N"
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

    if [ -z "$WEBTOB_HOME" ]; then
        RES="N/A"
        DESC="WebtoB 설치 경로를 찾을 수 없음"
        DT="WEBTOB_HOME: not found"
    else
        # 매뉴얼, 샘플 디렉터리 확인
        local FOUND_DIRS=""
        local FOUND_FILES=""

        [ -d "$WEBTOB_HOME/docs/manuals" ] && FOUND_DIRS="$FOUND_DIRS\n$WEBTOB_HOME/docs/manuals"
        [ -d "$WEBTOB_HOME/samples" ] && FOUND_DIRS="$FOUND_DIRS\n$WEBTOB_HOME/samples"
        [ -d "$WEBTOB_HOME/docs" ] && FOUND_DIRS="$FOUND_DIRS\n$WEBTOB_HOME/docs"

        # DOCROOT에서 불필요한 파일 확인
        local DOC_ROOT=""
        if [ -f "$WEBTOB_CONF" ]; then
            DOC_ROOT=$(grep -E "^\s*DOCROOT\s*=" "$WEBTOB_CONF" 2>/dev/null | grep -v "^\s*#" | head -1 | sed 's/.*=\s*"\?\([^",]*\).*/\1/')
        fi

        if [ -n "$DOC_ROOT" ] && [ -d "$DOC_ROOT" ]; then
            FOUND_FILES=$(find "$DOC_ROOT" -type f \( -name "*.bak" -o -name "*.backup" -o -name "*.old" -o -name "*.tmp" -o -name "*.swp" -o -name "README*" \) 2>/dev/null | head -10)
        fi

        if [ -z "$FOUND_DIRS" ] && [ -z "$FOUND_FILES" ]; then
            RES="Y"
            DESC="불필요한 파일 및 디렉터리가 없음"
            DT="매뉴얼/샘플 디렉터리: 없음\n불필요 파일: 없음"
        else
            RES="N"
            DESC="불필요한 파일 또는 디렉터리가 존재함"
            # 빈 값 처리
            local DIR_LIST="${FOUND_DIRS:-없음}"
            local FILE_LIST="${FOUND_FILES:-없음}"
            DT="발견된 디렉터리:$DIR_LIST\n불필요 파일:\n$FILE_LIST"
        fi
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

    if [ -z "$WEBTOB_CONF" ] || [ ! -f "$WEBTOB_CONF" ]; then
        RES="N/A"
        DESC="WebtoB 설정 파일을 찾을 수 없음"
        DT="WEBTOB_CONF: not found"
    else
        # LimitRequestBody 설정 확인
        local LIMIT_BODY=$(grep -E "^\s*LimitRequestBody" "$WEBTOB_CONF" 2>/dev/null | grep -v "^\s*#")

        if [ -n "$LIMIT_BODY" ]; then
            RES="Y"
            DESC="파일 업로드 용량 제한이 설정됨"
            DT="$LIMIT_BODY"
        else
            RES="N"
            DESC="파일 업로드 용량 제한이 설정되지 않음"
            DT="LimitRequestBody: 미설정\n\n권장: LimitRequestBody = 5242880 (5MB)"
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

    # WebtoB 프로세스 실행 계정 확인
    local WEBTOB_USER=$(ps aux 2>/dev/null | grep -E "(wsm|wsl|htl)" | grep -v grep | grep -v root | awk '{print $1}' | sort -u | head -1)

    # 설정 파일 소유자 확인
    local CONF_OWNER=""
    if [ -n "$WEBTOB_HOME" ] && [ -d "$WEBTOB_HOME" ]; then
        CONF_OWNER=$(stat -c "%U:%G" "$WEBTOB_HOME" 2>/dev/null)
    fi

    local CHECK_USER="${WEBTOB_USER:-$(echo $CONF_OWNER | cut -d':' -f1)}"

    if [ -z "$CHECK_USER" ]; then
        RES="M"
        DESC="WebtoB 실행 계정을 확인할 수 없음"
        DT="실행 중인 프로세스: 없음\n설치 디렉터리 소유자: ${CONF_OWNER:-미확인}"
    elif [ "$CHECK_USER" = "root" ]; then
        RES="N"
        DESC="WebtoB가 root 권한으로 실행 중"
        DT="실행 계정: $CHECK_USER\n\n권장: 별도의 전용 계정(예: tmax, webtob)으로 실행"
    else
        RES="Y"
        DESC="WebtoB가 제한된 권한으로 실행 중"
        DT="실행 계정: $CHECK_USER\n설치 디렉터리 소유자: ${CONF_OWNER:-미확인}"
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

    if [ -z "$WEBTOB_CONF" ] || [ ! -f "$WEBTOB_CONF" ]; then
        RES="N/A"
        DESC="WebtoB 설정 파일을 찾을 수 없음"
        DT="WEBTOB_CONF: not found"
    else
        # *REVERSE_PROXY 섹션 추출 (get_section 함수 사용)
        local PROXY_SECTION=$(get_section "REVERSE_PROXY")

        if [ -z "$PROXY_SECTION" ]; then
            RES="Y"
            DESC="프록시 설정이 비활성화되어 있음"
            DT="*REVERSE_PROXY: 미설정"
        else
            RES="M"
            DESC="프록시 설정 존재 (수동 확인 필요)"
            DT="*REVERSE_PROXY 설정:\n$PROXY_SECTION\n\n불필요한 프록시 설정 제거 권장"
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

    if [ -z "$WEBTOB_CONF" ] || [ ! -f "$WEBTOB_CONF" ]; then
        RES="N/A"
        DESC="WebtoB 설정 파일을 찾을 수 없음"
        DT="WEBTOB_CONF: not found"
    else
        # DOCROOT 설정 확인
        local DOC_ROOT=$(grep -E "^\s*DOCROOT\s*=" "$WEBTOB_CONF" 2>/dev/null | grep -v "^\s*#" | head -1)

        # 기본 경로 여부 확인
        local DEFAULT_PATHS=("/home/tmax/webtob/docs" "/home/webtob/webtob/docs" "/webtob/docs")
        local IS_DEFAULT="N"

        local DOC_ROOT_VALUE=$(echo "$DOC_ROOT" | sed 's/.*=\s*"\?\([^",]*\).*/\1/')

        for path in "${DEFAULT_PATHS[@]}"; do
            if [ "$DOC_ROOT_VALUE" = "$path" ]; then
                IS_DEFAULT="Y"
                break
            fi
        done

        if [ -z "$DOC_ROOT" ]; then
            RES="M"
            DESC="DOCROOT 설정을 찾을 수 없음"
            DT="DOCROOT: 미설정"
        elif [ "$IS_DEFAULT" = "Y" ]; then
            RES="M"
            DESC="기본 DOCROOT 경로 사용 중 (수동 확인 필요)"
            DT="$DOC_ROOT (기본 경로)"
        else
            RES="Y"
            DESC="별도의 DOCROOT 경로가 설정됨"
            DT="$DOC_ROOT"
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

    if [ -z "$WEBTOB_CONF" ] || [ ! -f "$WEBTOB_CONF" ]; then
        RES="N/A"
        DESC="WebtoB 설정 파일을 찾을 수 없음"
        DT="WEBTOB_CONF: not found"
    else
        # *ALIAS 섹션 추출 (get_section 함수 사용)
        local ALIAS_SECTION=$(get_section "ALIAS")

        if [ -z "$ALIAS_SECTION" ]; then
            RES="Y"
            DESC="ALIAS 설정이 없음"
            DT="*ALIAS: 미설정"
        else
            RES="M"
            DESC="ALIAS 설정 존재 (수동 확인 필요)"
            DT="*ALIAS 설정:\n$ALIAS_SECTION\n\n불필요한 ALIAS 설정 제거 권장"
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
    local DESC="해당 항목의 진단 대상이 아닙니다"
    local DT="WEB-14(웹 서비스 경로 내 파일의 접근 통제) 항목에서 통합 진단"

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

    if [ -z "$WEBTOB_CONF" ] || [ ! -f "$WEBTOB_CONF" ]; then
        RES="N/A"
        DESC="WebtoB 설정 파일을 찾을 수 없음"
        DT="WEBTOB_CONF: not found"
    else
        # 설정 파일 권한 확인
        local CONF_PERM=$(stat -c "%a" "$WEBTOB_CONF" 2>/dev/null)
        local CONF_OWNER=$(stat -c "%U:%G" "$WEBTOB_CONF" 2>/dev/null)

        # other 권한 확인 (마지막 자리)
        local OTHER_PERM=${CONF_PERM: -1}

        if [ "$OTHER_PERM" -eq 0 ]; then
            RES="Y"
            DESC="설정 파일에 적절한 권한이 설정됨"
            DT="$WEBTOB_CONF\n권한: $CONF_PERM\n소유자: $CONF_OWNER"
        else
            RES="N"
            DESC="설정 파일에 일반 사용자 접근 권한이 있음"
            DT="$WEBTOB_CONF\n권한: $CONF_PERM (other 권한 제거 필요)\n소유자: $CONF_OWNER\n\n권장: chmod 750 http.m"
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
    local DESC="해당 항목의 진단 대상이 아닙니다"
    local DT="WEB-05(지정하지 않은 CGI/ISAPI 실행 제한) 항목에서 통합 진단"

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

    if [ -z "$WEBTOB_CONF" ] || [ ! -f "$WEBTOB_CONF" ]; then
        RES="N/A"
        DESC="WebtoB 설정 파일을 찾을 수 없음"
        DT="WEBTOB_CONF: not found"
    else
        # ServerTokens, ServerSignature 설정 확인
        local SERVER_TOKENS=$(grep -E "^\s*ServerTokens" "$WEBTOB_CONF" 2>/dev/null | grep -v "^\s*#" | head -1)
        local SERVER_SIG=$(grep -E "^\s*ServerSignature" "$WEBTOB_CONF" 2>/dev/null | grep -v "^\s*#" | head -1)

        local IS_SECURE="Y"
        local ISSUES=""

        # ServerTokens가 Prod 또는 ProductOnly가 아니면 취약
        if [ -z "$SERVER_TOKENS" ]; then
            IS_SECURE="Y"  # 기본값이 off이므로 양호
            ISSUES="ServerTokens: 미설정 (기본값: off - 양호)"
        elif echo "$SERVER_TOKENS" | grep -qiE "(Prod|ProductOnly)"; then
            ISSUES="ServerTokens: 양호 - $SERVER_TOKENS"
        else
            IS_SECURE="N"
            ISSUES="ServerTokens: $SERVER_TOKENS (Prod 권장)"
        fi

        # ServerSignature가 Off가 아니면 취약
        if [ -z "$SERVER_SIG" ]; then
            ISSUES="$ISSUES\nServerSignature: 미설정 (기본값: off - 양호)"
        elif echo "$SERVER_SIG" | grep -qiE "off"; then
            ISSUES="$ISSUES\nServerSignature: 양호 - $SERVER_SIG"
        else
            IS_SECURE="N"
            ISSUES="$ISSUES\nServerSignature: $SERVER_SIG (Off 권장)"
        fi

        if [ "$IS_SECURE" = "Y" ]; then
            RES="Y"
            DESC="서버 헤더 정보 노출이 제한됨"
            DT="$ISSUES"
        else
            RES="N"
            DESC="서버 헤더 정보가 노출될 수 있음"
            DT="$ISSUES\n\n권장:\nServerTokens ProductOnly\nServerSignature off"
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

    if [ -z "$WEBTOB_CONF" ] || [ ! -f "$WEBTOB_CONF" ]; then
        RES="N/A"
        DESC="WebtoB 설정 파일을 찾을 수 없음"
        DT="WEBTOB_CONF: not found"
    else
        # *ALIAS 섹션 추출 (get_section 함수 사용)
        local ALIAS_SECTION=$(get_section "ALIAS")

        # cgi-bin, manual, docs 등 불필요한 설정 확인
        local UNNECESSARY_ALIAS=""
        if [ -n "$ALIAS_SECTION" ]; then
            UNNECESSARY_ALIAS=$(echo "$ALIAS_SECTION" | grep -iE "(cgi-bin|manual|docs|sample|test|backup)")
        fi

        if [ -z "$ALIAS_SECTION" ]; then
            RES="Y"
            DESC="불필요한 Alias 설정이 없음"
            DT="*ALIAS: 미설정"
        elif [ -n "$UNNECESSARY_ALIAS" ]; then
            RES="N"
            DESC="불필요한 가상 디렉터리 설정이 존재함"
            DT="불필요 Alias 설정:\n$UNNECESSARY_ALIAS"
        else
            RES="M"
            DESC="Alias 설정 존재 (수동 확인 필요)"
            DT="*ALIAS 설정:\n$ALIAS_SECTION"
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

    if [ -z "$WEBTOB_CONF" ] || [ ! -f "$WEBTOB_CONF" ]; then
        RES="N/A"
        DESC="WebtoB 설정 파일을 찾을 수 없음"
        DT="WEBTOB_CONF: not found"
    else
        # *VHOST 절에서 WebDAV 관련 메소드 확인 (PROPFIND, PUT, DELETE, MKCOL, COPY, MOVE)
        local WEBDAV_METHODS=$(grep -E "^\s*\w+.*Method\s*=" "$WEBTOB_CONF" 2>/dev/null | grep -v "^\s*#" | grep -iE "(PROPFIND|MKCOL|COPY|MOVE)")

        if [ -z "$WEBDAV_METHODS" ]; then
            RES="Y"
            DESC="WebDAV가 비활성화되어 있음"
            DT="WebDAV 관련 메소드: 미설정"
        else
            RES="N"
            DESC="WebDAV 관련 메소드가 허용되어 있음"
            DT="WebDAV 메소드 설정:\n$WEBDAV_METHODS\n\nPROPFIND, MKCOL, COPY, MOVE 메소드 제거 권장"
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

    if [ -z "$WEBTOB_CONF" ] || [ ! -f "$WEBTOB_CONF" ]; then
        RES="N/A"
        DESC="WebtoB 설정 파일을 찾을 수 없음"
        DT="WEBTOB_CONF: not found"
    else
        # *SVRGROUP, *SERVER 절에서 SSI 설정 확인 (대소문자 구분 없이 -i 옵션)
        local SSI_SVRGROUP=$(grep -iE "SVRTYPE\s*=\s*SSI" "$WEBTOB_CONF" 2>/dev/null | grep -v "^\s*#")
        local SSI_SERVER=$(grep -iE "^\s*ssi\s+.*SVGNAME\s*=" "$WEBTOB_CONF" 2>/dev/null | grep -v "^\s*#")

        local DETAILS=""
        [ -n "$SSI_SVRGROUP" ] && DETAILS="SSI SVRTYPE 설정:\n$SSI_SVRGROUP\n"
        [ -n "$SSI_SERVER" ] && DETAILS="${DETAILS}SSI SERVER 설정:\n$SSI_SERVER"

        if [ -z "$SSI_SVRGROUP" ] && [ -z "$SSI_SERVER" ]; then
            RES="Y"
            DESC="SSI가 비활성화되어 있음"
            DT="SSI SVRTYPE: 미설정\nSSI SERVER: 미설정"
        else
            RES="N"
            DESC="SSI가 활성화되어 있음"
            DT="$DETAILS\n\nSSI 설정 제거 또는 주석 처리 권장"
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

    if [ -z "$WEBTOB_CONF" ] || [ ! -f "$WEBTOB_CONF" ]; then
        RES="N/A"
        DESC="WebtoB 설정 파일을 찾을 수 없음"
        DT="WEBTOB_CONF: not found"
    else
        # *VHOST 절에서 SSLFLAG, SSLNAME 확인
        local SSL_FLAG=$(grep -E "^\s*\w+.*SSLFLAG\s*=\s*Y" "$WEBTOB_CONF" 2>/dev/null | grep -v "^\s*#")
        local SSL_NAME=$(grep -E "^\s*\w+.*SSLNAME\s*=" "$WEBTOB_CONF" 2>/dev/null | grep -v "^\s*#")

        # *SSL 절 확인
        local SSL_SECTION=$(awk '/^\*SSL/,/^\*[A-Z]/' "$WEBTOB_CONF" 2>/dev/null | grep -v "^\*" | grep -v "^\s*#" | grep -v "^$" | head -10)

        local DETAILS=""
        [ -n "$SSL_FLAG" ] && DETAILS="SSLFLAG:\n$SSL_FLAG\n"
        [ -n "$SSL_NAME" ] && DETAILS="${DETAILS}SSLNAME:\n$SSL_NAME\n"
        [ -n "$SSL_SECTION" ] && DETAILS="${DETAILS}\n*SSL 설정:\n$SSL_SECTION"

        if [ -n "$SSL_FLAG" ] && [ -n "$SSL_NAME" ]; then
            RES="Y"
            DESC="SSL/TLS가 활성화되어 있음"
            DT="$DETAILS"
        elif [ -n "$SSL_SECTION" ]; then
            RES="M"
            DESC="SSL 설정은 있으나 VHOST 적용 확인 필요"
            DT="$DETAILS"
        else
            RES="N"
            DESC="SSL/TLS가 비활성화되어 있음"
            DT="SSLFLAG: 미설정\nSSLNAME: 미설정\n\n권장:\n*VHOST 절에 SSLFLAG = Y, SSLNAME 설정\n*SSL 절에 인증서 경로 설정"
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

    if [ -z "$WEBTOB_CONF" ] || [ ! -f "$WEBTOB_CONF" ]; then
        RES="N/A"
        DESC="WebtoB 설정 파일을 찾을 수 없음"
        DT="WEBTOB_CONF: not found"
    else
        # URLRewrite, URLRewriteConfig 설정 확인 (들여쓰기된 설정도 매칭)
        local URL_REWRITE=$(grep -iE "URLRewrite\s*=\s*Y" "$WEBTOB_CONF" 2>/dev/null | grep -v "^\s*#")
        local URL_REWRITE_CONFIG=$(grep -iE "URLRewriteConfig\s*=" "$WEBTOB_CONF" 2>/dev/null | grep -v "^\s*#")

        # URLRewriteConfig 파일에서 HTTPS 리디렉션 확인
        local REWRITE_FILE=""
        local HTTPS_REDIRECT=""
        if [ -n "$URL_REWRITE_CONFIG" ]; then
            REWRITE_FILE=$(echo "$URL_REWRITE_CONFIG" | sed 's/.*=\s*"\?\([^",]*\).*/\1/')
            if [ -n "$WEBTOB_HOME" ] && [ -f "$WEBTOB_HOME/$REWRITE_FILE" ]; then
                HTTPS_REDIRECT=$(grep -iE "RewriteRule.*https|HTTPS.*off" "$WEBTOB_HOME/$REWRITE_FILE" 2>/dev/null)
            elif [ -f "$REWRITE_FILE" ]; then
                HTTPS_REDIRECT=$(grep -iE "RewriteRule.*https|HTTPS.*off" "$REWRITE_FILE" 2>/dev/null)
            fi
        fi

        if [ -n "$URL_REWRITE" ] && [ -n "$HTTPS_REDIRECT" ]; then
            RES="Y"
            DESC="HTTP to HTTPS 리디렉션이 설정됨"
            DT="URLRewrite:\n$URL_REWRITE\nURLRewriteConfig:\n$URL_REWRITE_CONFIG\n\nRewrite 규칙:\n$HTTPS_REDIRECT"
        elif [ -n "$URL_REWRITE" ]; then
            RES="M"
            DESC="URLRewrite 설정 있음 (HTTPS 리디렉션 확인 필요)"
            DT="URLRewrite:\n$URL_REWRITE\nURLRewriteConfig:\n${URL_REWRITE_CONFIG:-미설정}"
        else
            RES="N"
            DESC="HTTP to HTTPS 리디렉션이 설정되지 않음"
            DT="URLRewrite: 미설정\n\n권장:\n*VHOST 절에 URLRewrite = Y, URLRewriteConfig 설정\nrewrite 파일에 HTTPS 리디렉션 규칙 추가"
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

    if [ -z "$WEBTOB_CONF" ] || [ ! -f "$WEBTOB_CONF" ]; then
        RES="N/A"
        DESC="WebtoB 설정 파일을 찾을 수 없음"
        DT="WEBTOB_CONF: not found"
    else
        # *ERRORDOCUMENT 섹션 추출 (get_section 함수 사용)
        local ERROR_DOC=$(get_section "ERRORDOCUMENT")

        # VHOST, NODE에서 ERRORDOCUMENT 참조 확인 (대소문자 구분 없이)
        local ERROR_REF=$(grep -iE "ERRORDOCUMENT\s*=" "$WEBTOB_CONF" 2>/dev/null | grep -v "^\s*#")

        if [ -n "$ERROR_DOC" ] || [ -n "$ERROR_REF" ]; then
            RES="Y"
            DESC="에러 페이지가 설정되어 있음"
            DT="*ERRORDOCUMENT 설정:\n${ERROR_DOC:-미설정}\n\nERRORDOCUMENT 참조:\n${ERROR_REF:-미설정}"
        else
            RES="N"
            DESC="에러 페이지가 설정되지 않음"
            DT="*ERRORDOCUMENT: 미설정\n\n권장:\n*ERRORDOCUMENT 절에 에러 코드별 페이지 설정\n*VHOST 또는 *NODE 절에서 ERRORDOCUMENT 참조"
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
    local DESC="WebtoB는 웹서버로서 LDAP 인증을 지원하지 않음"
    local DT="WebtoB는 웹 서버로서 LDAP 인증 기능을 내장하고 있지 않습니다.\nLDAP 인증이 필요한 경우 WAS(JEUS 등)와 연동하거나 별도의 인증 모듈을 사용하므로 해당 항목은 적용 대상이 아닙니다."

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

    if [ -z "$WEBTOB_CONF" ] || [ ! -f "$WEBTOB_CONF" ]; then
        RES="N/A"
        DESC="WebtoB 설정 파일을 찾을 수 없음"
        DT="WEBTOB_CONF: not found"
    else
        # *ALIAS 섹션에서 upload 관련 설정 확인 (get_section 함수 사용)
        local ALIAS_SECTION=$(get_section "ALIAS")
        local UPLOAD_ALIAS=""
        if [ -n "$ALIAS_SECTION" ]; then
            UPLOAD_ALIAS=$(echo "$ALIAS_SECTION" | grep -iE "upload")
        fi

        if [ -n "$UPLOAD_ALIAS" ]; then
            # 업로드 경로 추출
            local UPLOAD_PATH=$(echo "$UPLOAD_ALIAS" | sed 's/.*RealPath\s*=\s*"\?\([^",]*\).*/\1/' | head -1)

            if [ -n "$UPLOAD_PATH" ] && [ -d "$UPLOAD_PATH" ]; then
                local PERM=$(stat -c "%a" "$UPLOAD_PATH" 2>/dev/null)
                local OWNER=$(stat -c "%U:%G" "$UPLOAD_PATH" 2>/dev/null)
                local OTHER_PERM=${PERM: -1}

                if [ "$OTHER_PERM" -eq 0 ]; then
                    RES="Y"
                    DESC="업로드 디렉터리에 적절한 권한이 설정됨"
                    DT="업로드 경로: $UPLOAD_PATH\n권한: $PERM\n소유자: $OWNER"
                else
                    RES="N"
                    DESC="업로드 디렉터리에 일반 사용자 접근 권한이 있음"
                    DT="업로드 경로: $UPLOAD_PATH\n권한: $PERM (other 권한 제거 필요)\n소유자: $OWNER\n\n권장: chmod 750"
                fi
            else
                RES="M"
                DESC="업로드 경로 설정 확인 필요"
                DT="*ALIAS upload 설정:\n$UPLOAD_ALIAS"
            fi
        else
            RES="M"
            DESC="업로드 경로 설정을 찾을 수 없음 (수동 확인 필요)"
            DT="*ALIAS upload 관련 설정: 미설정"
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

    # WebtoB 버전 확인
    local VERSION=""
    if command -v wscfl &>/dev/null; then
        VERSION=$(wscfl -version 2>/dev/null)
    elif [ -n "$WEBTOB_HOME" ] && [ -x "$WEBTOB_HOME/bin/wscfl" ]; then
        VERSION=$("$WEBTOB_HOME/bin/wscfl" -version 2>/dev/null)
    fi

    if [ -z "$VERSION" ]; then
        RES="N/A"
        DESC="WebtoB 버전을 확인할 수 없음"
        DT="wscfl 명령어를 찾을 수 없음"
    else
        RES="M"
        DESC="버전 정보 확인 (수동 패치 확인 필요)"
        DT="$VERSION\n\n최신 버전 확인: https://technet.tmaxsoft.com/ko/front/download/findDownloadList.do?cmProductCode=0102"
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

    if [ -z "$WEBTOB_HOME" ]; then
        RES="N/A"
        DESC="WebtoB 설치 경로를 찾을 수 없음"
        DT="WEBTOB_HOME: not found"
    else
        # 로그 디렉터리 찾기
        local LOG_DIR=""
        if [ -d "$WEBTOB_HOME/log" ]; then
            LOG_DIR="$WEBTOB_HOME/log"
        elif [ -d "$WEBTOB_HOME/logs" ]; then
            LOG_DIR="$WEBTOB_HOME/logs"
        fi

        if [ -z "$LOG_DIR" ]; then
            RES="M"
            DESC="로그 디렉터리를 찾을 수 없음 (수동 확인 필요)"
            DT="일반적인 경로에 로그 디렉터리 없음"
        else
            local DIR_PERM=$(stat -c "%a" "$LOG_DIR" 2>/dev/null)
            local DIR_OWNER=$(stat -c "%U:%G" "$LOG_DIR" 2>/dev/null)
            local OTHER_PERM=${DIR_PERM: -1}

            # 로그 파일 권한 확인
            local LOG_FILES=$(find "$LOG_DIR" -type f -name "*.log*" 2>/dev/null | head -3)
            local FILE_PERMS=""
            for f in $LOG_FILES; do
                local F_PERM=$(stat -c "%a %n" "$f" 2>/dev/null)
                FILE_PERMS="$FILE_PERMS\n$F_PERM"
            done

            if [ "$OTHER_PERM" -eq 0 ]; then
                RES="Y"
                DESC="로그 디렉터리에 적절한 권한이 설정됨"
                DT="$LOG_DIR - 권한: $DIR_PERM, 소유자: $DIR_OWNER\n로그 파일:$FILE_PERMS"
            else
                RES="N"
                DESC="로그 디렉터리에 일반 사용자 접근 권한이 있음"
                DT="$LOG_DIR - 권한: $DIR_PERM (other 권한 제거 필요)\n소유자: $DIR_OWNER\n로그 파일:$FILE_PERMS\n\n권장: chmod 750 $LOG_DIR"
            fi
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
