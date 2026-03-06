#!/bin/ksh
#================================================================
# HP-UX 보안 진단 스크립트
# KISA 주요정보통신기반시설 기술적 취약점 분석·평가 기준
#================================================================
# 버전  : 2603070
# 대상  : HP-UX 11i v2, v3
# 항목  : U-01 ~ U-67 (67개)
# 제작  : Seedgen
#================================================================
META_STD="KISA"

#================================================================
# INIT
#================================================================
META_VER="1.0"
META_PLAT="HP-UX"
META_TYPE="Server"

# 권한 체크
if [ "$(id -u)" -ne 0 ]; then
    echo "[!] root 권한으로 실행하세요."
    exit 1
fi

# XML 특수문자 이스케이프
xml_escape() {
    typeset s="$1"
    s=$(echo "$s" | sed 's/&/\&amp;/g; s/</\&lt;/g; s/>/\&gt;/g; s/"/\&quot;/g')
    echo "$s"
}

# 결과 출력 함수
output_checkpoint() {
    typeset CODE="$1"
    typeset CAT="$2"
    typeset NAME="$3"
    typeset IMP="$4"
    typeset STD="$5"
    typeset RES="$6"
    typeset DESC="$7"
    typeset DT="$8"

    # 콘솔 출력
    case "$RES" in
        "Y")   printf "    [[32mY[0m] %s %s
#================================================================
# HP-UX 보안 진단 스크립트
# KISA 주요정보통신기반시설 기술적 취약점 분석·평가 기준
#================================================================
# 버전  : 2603070
# 대상  : HP-UX 11i v2, v3
# 항목  : U-01 ~ U-67 (67개)
# 제작  : Seedgen
#================================================================
META_STD="KISA"

#================================================================
# INIT
#================================================================
META_VER="1.0"
META_PLAT="HP-UX"
META_TYPE="Server"

# 권한 체크
if [ "$(id -u)" -ne 0 ]; then
    echo "[!] root 권한으로 실행하세요."
    exit 1
fi

# XML 특수문자 이스케이프
xml_escape() {
    typeset s="$1"
    s=$(echo "$s" | sed 's/&/\&amp;/g; s/</\&lt;/g; s/>/\&gt;/g; s/"/\&quot;/g')
    echo "$s"
}

# 결과 출력 함수
output_checkpoint() {
    typeset CODE="$1"
    typeset CAT="$2"
    typeset NAME="$3"
    typeset IMP="$4"
    typeset STD="$5"
    typeset RES="$6"
    typeset DESC="$7"
    typeset DT="$8"

    # 콘솔 출력
    case "$RES" in
        "Y")   printf "    [\033[32mY\033[0m] %s %s\n" "$CODE" "$NAME" ;;
        "N")   printf "    [\033[31mN\033[0m] %s %s\n" "$CODE" "$NAME" ;;
        "M")   printf "    [\033[33mM\033[0m] %s %s\n" "$CODE" "$NAME" ;;
        "N/A") printf "    [\033[90m-\033[0m] %s %s\n" "$CODE" "$NAME" ;;
        *)     printf "    [-] %s %s\n" "$CODE" "$NAME" ;;
    esac

    # XML 출력
    typeset E_NAME; E_NAME=$(xml_escape "$NAME")
    typeset E_DESC; E_DESC=$(xml_escape "$DESC")
    typeset E_STD; E_STD=$(xml_escape "$STD")
    printf "        <cp>\n" >> "$OUTPUT_FILE"
    printf "            <code>%s</code>\n" "$CODE" >> "$OUTPUT_FILE"
    printf "            <cat>%s</cat>\n" "$CAT" >> "$OUTPUT_FILE"
    printf "            <n>%s</n>\n" "$E_NAME" >> "$OUTPUT_FILE"
    printf "            <imp>%s</imp>\n" "$IMP" >> "$OUTPUT_FILE"
    printf "            <std>%s</std>\n" "$E_STD" >> "$OUTPUT_FILE"
    printf "            <res>%s</res>\n" "$RES" >> "$OUTPUT_FILE"
    printf "            <desc>%s</desc>\n" "$E_DESC" >> "$OUTPUT_FILE"
    printf "            <dt><![CDATA[%s]]></dt>\n" "$DT" >> "$OUTPUT_FILE"
    printf "        </cp>\n" >> "$OUTPUT_FILE"
}

#================================================================
# POSIX 호환 유틸리티 함수
#================================================================

get_file_perm() {
    ls -ld "$1" 2>/dev/null | awk '{
        p=substr($1,2,9); m=0
        if(substr(p,1,1)=="r")m+=400; if(substr(p,2,1)=="w")m+=200; if(substr(p,3,1)~/[xsS]/)m+=100
        if(substr(p,4,1)=="r")m+=40;  if(substr(p,5,1)=="w")m+=20;  if(substr(p,6,1)~/[xsS]/)m+=10
        if(substr(p,7,1)=="r")m+=4;   if(substr(p,8,1)=="w")m+=2;   if(substr(p,9,1)~/[xtT]/)m+=1
        printf "%03d",m
    }'
}

get_file_owner() { ls -ld "$1" 2>/dev/null | awk '{print $3}'; }
get_file_group() { ls -ld "$1" 2>/dev/null | awk '{print $4}'; }
to_lower() { echo "$1" | tr 'A-Z' 'a-z'; }
to_upper() { echo "$1" | tr 'a-z' 'A-Z'; }

is_process_running() {
    ps -ef 2>/dev/null | grep -v grep | grep -q "$1"
}

matches_pattern() {
    typeset string="$1"; typeset pattern="$2"
    echo "$string" | grep -qE "$pattern"
}

contains_string() {
    typeset string="$1"; typeset substring="$2"
    case "$string" in *"$substring"*) return 0 ;; *) return 1 ;; esac
}

is_number() {
    case "$1" in ''|*[!0-9]*) return 1 ;; *) return 0 ;; esac
}

#================================================================
# HP-UX 플랫폼 헬퍼
#================================================================

# 서비스 실행 확인 (HP-UX)
is_service_running() {
    typeset service="$1"
    ps -ef 2>/dev/null | grep -v grep | grep -q "$service"
}

# HP-UX 설정 파일 경로
SSHD_CONFIG="/opt/ssh/etc/sshd_config"
if [ ! -f "$SSHD_CONFIG" ]; then
    SSHD_CONFIG="/etc/ssh/sshd_config"
fi

SECURITY_CONFIG="/etc/default/security"
TCB_AUTH="/tcb/files/auth/system/default"
LOGIN_DEFS="/etc/default/security"

#================================================================
# COLLECT — 시스템 정보 수집 (HP-UX)
#================================================================

META_DATE=$(date +%Y-%m-%dT%H:%M:%S)
SYS_HOST=$(hostname)
SYS_DOM=$(domainname 2>/dev/null || echo "N/A")
SYS_OS_NAME="HP-UX $(uname -r)"
SYS_OS_FN="HP-UX"
SYS_KN=$(uname -r)
SYS_ARCH=$(uname -m)

# HP-UX IP 주소 수집 (lanscan + ifconfig)
SYS_IP=$(lanscan 2>/dev/null | awk '/^[0-9]/ {print $5}' | head -1 | xargs -I{} ifconfig {} 2>/dev/null | grep "inet " | awk '{print $2}' | head -1)
if [ -z "$SYS_IP" ]; then
    SYS_IP=$(netstat -in 2>/dev/null | awk 'NR>1 && $1!~/lo/ {print $4}' | head -1)
fi

SYS_NET_ALL=$(lanscan 2>/dev/null | awk '/^[0-9]/ {print $5}' | while read iface; do
    ifconfig "$iface" 2>/dev/null | grep "inet " | awk -v i="$iface" '{print i": "$2}'
done)

# 출력 파일 경로
SCRIPT_DIR=$(cd "$(dirname "$0")" && pwd)
OUTPUT_FILE="${SCRIPT_DIR}/${META_PLAT}_${SYS_HOST}_$(date +%Y%m%d_%H%M%S).xml"

#================================================================
# CHECK FUNCTIONS
#================================================================

check01() {
    local CODE="U-01"
    local CAT="계정관리"
    local NAME="root 계정 원격 접속 제한"
    local IMP="상"
    local STD="원격터미널 서비스를 사용하지 않거나, 사용 시 root 직접 접속을 차단한 경우"
    local RES=""
    local DESC=""
    local DT=""

        typeset SSH_SECURE="N"
        typeset TELNET_SECURE="N"
        typeset DETAILS=""

        # SSH 설정 확인 (HP-UX: /opt/ssh/etc/sshd_config 우선, /etc/ssh/sshd_config 대체)
        if [ -f "$SSHD_CONFIG" ]; then
            typeset PERMIT=""
            PERMIT=$(grep -i "^PermitRootLogin" "$SSHD_CONFIG" 2>/dev/null | awk '{print $2}' | head -1)
            typeset PERMIT_LOWER=""
            PERMIT_LOWER=$(to_lower "$PERMIT")
            if [ "$PERMIT_LOWER" = "no" ]; then
                SSH_SECURE="Y"
            fi
            DETAILS="SSH($SSHD_CONFIG) PermitRootLogin: ${PERMIT:-not set}"
        else
            DETAILS="SSH 설정 파일 없음"
        fi

        # Telnet 설정 확인 (HP-UX: /etc/securetty에 console만 존재해야 함)
        typeset SECURETTY="/etc/securetty"
        if [ -f "$SECURETTY" ]; then
            typeset CONSOLE_ONLY=""
            CONSOLE_ONLY=$(grep -v "^#" "$SECURETTY" 2>/dev/null | grep -v "^$" | head -1)
            if [ "$CONSOLE_ONLY" = "console" ]; then
                TELNET_SECURE="Y"
            fi
            DETAILS="${DETAILS}
    Telnet securetty: ${CONSOLE_ONLY:-empty}"
        else
            DETAILS="${DETAILS}
    /etc/securetty: 파일 없음 (Telnet root 접속 가능)"
        fi

        # Telnet 서비스 실행 여부 확인
        typeset TELNET_RUNNING="N"
        if is_process_running "telnetd"; then
            TELNET_RUNNING="Y"
        fi

        # SSH 서비스 실행 여부 확인
        typeset SSH_RUNNING="N"
        if is_process_running "sshd"; then
            SSH_RUNNING="Y"
        fi

        # 판단: 원격 서비스 미사용 시 양호, 사용 시 root 접속 차단 여부 확인
        if [ "$SSH_RUNNING" = "N" ] && [ "$TELNET_RUNNING" = "N" ]; then
            RES="Y"
            DESC="원격터미널 서비스를 사용하지 않음"
        elif [ "$SSH_RUNNING" = "Y" ] && [ "$SSH_SECURE" = "Y" ]; then
            RES="Y"
            DESC="root 원격 접속이 제한되어 있음"
        elif [ "$SSH_RUNNING" = "Y" ] && [ "$SSH_SECURE" = "N" ]; then
            RES="N"
            DESC="root 원격 접속이 허용되어 있음"
        elif [ "$TELNET_RUNNING" = "Y" ] && [ "$TELNET_SECURE" = "N" ]; then
            RES="N"
            DESC="Telnet root 원격 접속이 허용되어 있음"
        else
            RES="Y"
            DESC="root 원격 접속이 제한되어 있음"
        fi

        DT="SSH 실행: $SSH_RUNNING, Telnet 실행: $TELNET_RUNNING
    $DETAILS"

    output_checkpoint "$CODE" "$CAT" "$NAME" "$IMP" "$STD" "$RES" "$DESC" "$DT"
}

check02() {
    local CODE="U-02"
    local CAT="계정관리"
    local NAME="비밀번호 관리정책 설정"
    local IMP="상"
    local STD="비밀번호 관리 정책이 설정된 경우"
    local RES=""
    local DESC=""
    local DT=""

        typeset ISSUES=""
        typeset DETAILS=""

        # HP-UX: /etc/default/security 파일 확인
        typeset MIN_LEN=""
        typeset MAX_DAYS=""
        typeset MIN_DAYS=""
        typeset MIN_UPPER=""
        typeset MIN_LOWER=""
        typeset MIN_DIGIT=""
        typeset MIN_SPECIAL=""
        typeset HISTORY_VAL=""

        if [ -f "$SECURITY_CONFIG" ]; then
            MIN_LEN=$(grep "^MIN_PASSWORD_LENGTH" "$SECURITY_CONFIG" 2>/dev/null | cut -d'=' -f2 | tr -d ' ')
            MAX_DAYS=$(grep "^PASSWORD_MAXDAYS" "$SECURITY_CONFIG" 2>/dev/null | cut -d'=' -f2 | tr -d ' ')
            MIN_DAYS=$(grep "^PASSWORD_MINDAYS" "$SECURITY_CONFIG" 2>/dev/null | cut -d'=' -f2 | tr -d ' ')
            MIN_UPPER=$(grep "^PASSWORD_MIN_UPPER_CASE_CHARS" "$SECURITY_CONFIG" 2>/dev/null | cut -d'=' -f2 | tr -d ' ')
            MIN_LOWER=$(grep "^PASSWORD_MIN_LOWER_CASE_CHARS" "$SECURITY_CONFIG" 2>/dev/null | cut -d'=' -f2 | tr -d ' ')
            MIN_DIGIT=$(grep "^PASSWORD_MIN_DIGIT_CHARS" "$SECURITY_CONFIG" 2>/dev/null | cut -d'=' -f2 | tr -d ' ')
            MIN_SPECIAL=$(grep "^PASSWORD_MIN_SPECIAL_CHARS" "$SECURITY_CONFIG" 2>/dev/null | cut -d'=' -f2 | tr -d ' ')
            HISTORY_VAL=$(grep "^HISTORY" "$SECURITY_CONFIG" 2>/dev/null | cut -d'=' -f2 | tr -d ' ')

            DETAILS="MIN_PASSWORD_LENGTH: ${MIN_LEN:-not set}
    PASSWORD_MAXDAYS: ${MAX_DAYS:-not set}
    PASSWORD_MINDAYS: ${MIN_DAYS:-not set}
    PASSWORD_MIN_UPPER_CASE_CHARS: ${MIN_UPPER:-not set}
    PASSWORD_MIN_LOWER_CASE_CHARS: ${MIN_LOWER:-not set}
    PASSWORD_MIN_DIGIT_CHARS: ${MIN_DIGIT:-not set}
    PASSWORD_MIN_SPECIAL_CHARS: ${MIN_SPECIAL:-not set}
    HISTORY: ${HISTORY_VAL:-not set}"
        else
            DETAILS="$SECURITY_CONFIG: 파일 없음"
        fi

        # 판단
        typeset IS_OK="true"

        if [ -z "$MAX_DAYS" ]; then
            IS_OK="false"
            ISSUES="${ISSUES}PASSWORD_MAXDAYS 미설정, "
        elif is_number "$MAX_DAYS" && [ "$MAX_DAYS" -gt 90 ]; then
            IS_OK="false"
            ISSUES="${ISSUES}PASSWORD_MAXDAYS 90일 초과($MAX_DAYS), "
        fi

        if [ -z "$MIN_DAYS" ]; then
            IS_OK="false"
            ISSUES="${ISSUES}PASSWORD_MINDAYS 미설정, "
        elif is_number "$MIN_DAYS" && [ "$MIN_DAYS" -lt 1 ]; then
            IS_OK="false"
            ISSUES="${ISSUES}PASSWORD_MINDAYS 1일 미만($MIN_DAYS), "
        fi

        if [ -z "$MIN_LEN" ]; then
            IS_OK="false"
            ISSUES="${ISSUES}MIN_PASSWORD_LENGTH 미설정, "
        elif is_number "$MIN_LEN" && [ "$MIN_LEN" -lt 8 ]; then
            IS_OK="false"
            ISSUES="${ISSUES}MIN_PASSWORD_LENGTH 8자 미만($MIN_LEN), "
        fi

        if [ "$IS_OK" = "true" ]; then
            RES="Y"
            DESC="비밀번호 관리정책이 적절히 설정됨"
        else
            RES="N"
            DESC="비밀번호 관리정책 미흡 (${ISSUES%%, })"
        fi

        DT="$DETAILS"

    output_checkpoint "$CODE" "$CAT" "$NAME" "$IMP" "$STD" "$RES" "$DESC" "$DT"
}

check03() {
    local CODE="U-03"
    local CAT="계정관리"
    local NAME="계정 잠금 임계값 설정"
    local IMP="상"
    local STD="계정 잠금 임계값이 10회 이하의 값으로 설정된 경우"
    local RES=""
    local DESC=""
    local DT=""

    typeset DENY_VALUE=""
    typeset DETAILS=""

    # HP-UX 11.v3 이상: /etc/default/security - AUTH_MAXTRIES
    if [ -f "$SECURITY_CONFIG" ]; then
        DENY_VALUE=$(grep "^AUTH_MAXTRIES" "$SECURITY_CONFIG" 2>/dev/null | cut -d'=' -f2 | tr -d ' ')
        if [ -n "$DENY_VALUE" ]; then
            DETAILS="AUTH_MAXTRIES: $DENY_VALUE ($SECURITY_CONFIG)"
        fi
    fi

    # HP-UX 11.v2 이하 (Trusted Mode): /tcb/files/auth/system/default - u_maxtries
    if [ -z "$DENY_VALUE" ] && [ -f "$TCB_AUTH" ]; then
        DENY_VALUE=$(grep "u_maxtries" "$TCB_AUTH" 2>/dev/null | sed 's/.*u_maxtries#//' | cut -d':' -f1)
        if [ -n "$DENY_VALUE" ]; then
            DETAILS="u_maxtries: $DENY_VALUE (Trusted Mode)"
        fi
    fi

    # 판단
    if [ -z "$DENY_VALUE" ]; then
        RES="N"
        DESC="계정 잠금 임계값이 설정되지 않음"
        DT="AUTH_MAXTRIES/u_maxtries: not set"
    elif is_number "$DENY_VALUE" && [ "$DENY_VALUE" -le 10 ]; then
        RES="Y"
        DESC="계정 잠금 임계값이 적절히 설정됨"
        DT="$DETAILS"
    else
        RES="N"
        DESC="계정 잠금 임계값이 10회 초과"
        DT="$DETAILS (기준: 10회 이하)"
    fi

    output_checkpoint "$CODE" "$CAT" "$NAME" "$IMP" "$STD" "$RES" "$DESC" "$DT"
}

check04() {
    local CODE="U-04"
    local CAT="계정관리"
    local NAME="비밀번호 파일 보호"
    local IMP="상"
    local STD="쉐도우 비밀번호를 사용하거나, 비밀번호를 암호화하여 저장하는 경우"
    local RES=""
    local DESC=""
    local DT=""

        # /etc/passwd 두 번째 필드 확인 (x가 아닌 계정 = 평문 비밀번호)
        typeset UNPROTECTED=""
        UNPROTECTED=$(awk -F: '$2 != "x" && $2 != "" {print $1}' /etc/passwd 2>/dev/null)

        # /etc/shadow 파일 존재 여부
        typeset SHADOW_EXISTS="N"
        if [ -f /etc/shadow ]; then
            SHADOW_EXISTS="Y"
        fi

        # HP-UX Trusted Mode: /tcb/files/auth 디렉토리 존재 여부
        typeset TCB_EXISTS="N"
        if [ -d /tcb/files/auth ]; then
            TCB_EXISTS="Y"
        fi

        typeset DETAILS=""
        DETAILS="/etc/passwd 두 번째 필드: $([ -z "$UNPROTECTED" ] && printf 'x (암호화됨)' || printf '평문 존재')
    /etc/shadow: $([ "$SHADOW_EXISTS" = "Y" ] && printf '존재함' || printf '없음')
    /tcb/files/auth (Trusted Mode): $([ "$TCB_EXISTS" = "Y" ] && printf '존재함' || printf '없음')"

        if [ -z "$UNPROTECTED" ] && { [ "$SHADOW_EXISTS" = "Y" ] || [ "$TCB_EXISTS" = "Y" ]; }; then
            RES="Y"
            DESC="비밀번호가 암호화되어 저장됨"
        else
            RES="N"
            DESC="비밀번호 파일 보호 미흡"
            if [ -n "$UNPROTECTED" ]; then
                DETAILS="${DETAILS}
    쉐도우 미사용 계정: $UNPROTECTED"
            fi
        fi

        DT="$DETAILS"

    output_checkpoint "$CODE" "$CAT" "$NAME" "$IMP" "$STD" "$RES" "$DESC" "$DT"
}

check05() {
    local CODE="U-05"
    local CAT="계정관리"
    local NAME="root 이외의 UID가 ‘0’ 금지"
    local IMP="상"
    local STD="root 계정과 동일한 UID를 갖는 계정이 존재하지 않는 경우"
    local RES=""
    local DESC=""
    local DT=""

    # UID가 0인 계정 확인 (root 제외)
    typeset UID0_ACCOUNTS=""
    UID0_ACCOUNTS=$(awk -F: '$3 == 0 && $1 != "root" {print $1}' /etc/passwd 2>/dev/null)

    if [ -z "$UID0_ACCOUNTS" ]; then
        RES="Y"
        DESC="root 외 UID=0 계정이 존재하지 않음"
        DT="UID=0 계정: root만 존재"
    else
        RES="N"
        DESC="root 외 UID=0 계정이 존재함"
        DT="UID=0 계정: root, $UID0_ACCOUNTS"
    fi

    output_checkpoint "$CODE" "$CAT" "$NAME" "$IMP" "$STD" "$RES" "$DESC" "$DT"
}

check06() {
    local CODE="U-06"
    local CAT="계정관리"
    local NAME="사용자 계정 su 기능 제한"
    local IMP="상"
    local STD="su 명령어를 특정 그룹에 속한 사용자만 사용하도록 제한된 경우"
    local RES=""
    local DESC=""
    local DT=""

        typeset DETAILS=""
        typeset IS_RESTRICTED="false"

        # wheel 그룹 확인
        typeset WHEEL_GROUP=""
        WHEEL_GROUP=$(grep "^wheel:" /etc/group 2>/dev/null)
        DETAILS="wheel 그룹: ${WHEEL_GROUP:-없음}"

        # su 명령어 권한 및 그룹 확인 (HP-UX: /usr/bin/su)
        typeset SU_PERM=""
        typeset SU_GROUP=""
        if [ -f /usr/bin/su ]; then
            SU_PERM=$(get_file_perm /usr/bin/su 2>/dev/null)
            SU_GROUP=$(get_file_group /usr/bin/su 2>/dev/null)
            DETAILS="${DETAILS}
    su 권한: ${SU_PERM:-확인불가}
    su 그룹: ${SU_GROUP:-확인불가}"

            # su 명령어가 wheel 그룹에 속하고 4750 이하 권한인지 확인
            if [ "$SU_GROUP" = "wheel" ]; then
                case "$SU_PERM" in
                    4750|4710|4700) IS_RESTRICTED="true" ;;
                esac
            fi
        fi

        if [ "$IS_RESTRICTED" = "true" ]; then
            RES="Y"
            DESC="su 명령어가 특정 그룹에만 허용됨"
        else
            RES="N"
            DESC="su 명령어가 모든 사용자에게 허용됨"
        fi

        DT="$DETAILS"

    output_checkpoint "$CODE" "$CAT" "$NAME" "$IMP" "$STD" "$RES" "$DESC" "$DT"
}

check07() {
    local CODE="U-07"
    local CAT="계정관리"
    local NAME="불필요한 계정 제거"
    local IMP="하"
    local STD="불필요한 계정이 존재하지 않는 경우"
    local RES=""
    local DESC=""
    local DT=""

        # 기본 불필요 계정 목록
        typeset UNNECESSARY="lp uucp nuucp"
        typeset FOUND_ACCOUNTS=""

        for acc in $UNNECESSARY; do
            if grep -q "^${acc}:" /etc/passwd 2>/dev/null; then
                FOUND_ACCOUNTS="${FOUND_ACCOUNTS}${acc} "
            fi
        done

        # 로그인 가능한 일반 계정 목록 (HP-UX: UID >= 100)
        typeset LOGIN_ACCOUNTS=""
        LOGIN_ACCOUNTS=$(awk -F: '$3 >= 100 && $7 !~ /nologin|false/ {print $1}' /etc/passwd 2>/dev/null | tr '\n' ' ')

        if [ -n "$FOUND_ACCOUNTS" ]; then
            RES="N"
            DESC="불필요한 기본 계정이 존재함"
            DT="불필요 계정: $FOUND_ACCOUNTS"
        else
            RES="M"
            DESC="불필요한 계정 수동 확인 필요"
            DT="확인된 불필요 계정: 없음
    로그인 가능 계정: ${LOGIN_ACCOUNTS:-없음}"
        fi

    output_checkpoint "$CODE" "$CAT" "$NAME" "$IMP" "$STD" "$RES" "$DESC" "$DT"
}

check08() {
    local CODE="U-08"
    local CAT="계정관리"
    local NAME="관리자 그룹에 최소한의 계정 포함"
    local IMP="중"
    local STD="관리자 그룹에 불필요한 계정이 등록되어 있지 않은 경우"
    local RES=""
    local DESC=""
    local DT=""

        # root 그룹 (GID=0) 확인
        typeset ROOT_GROUP=""
        ROOT_GROUP=$(grep "^root:" /etc/group 2>/dev/null)
        typeset ROOT_MEMBERS=""
        ROOT_MEMBERS=$(echo "$ROOT_GROUP" | cut -d: -f4)

        # sys 그룹 확인 (HP-UX 관리자 그룹)
        typeset SYS_GROUP=""
        SYS_GROUP=$(grep "^sys:" /etc/group 2>/dev/null)
        typeset SYS_MEMBERS=""
        SYS_MEMBERS=$(echo "$SYS_GROUP" | cut -d: -f4)

        typeset DETAILS=""
        DETAILS="root 그룹: ${ROOT_GROUP:-없음}
    sys 그룹: ${SYS_GROUP:-없음}"

        if [ -z "$ROOT_MEMBERS" ] && [ -z "$SYS_MEMBERS" ]; then
            RES="Y"
            DESC="관리자 그룹에 추가 계정이 없음"
        else
            RES="M"
            DESC="관리자 그룹에 계정 존재, 수동 확인 필요"
            DETAILS="${DETAILS}
    root 그룹 멤버: ${ROOT_MEMBERS:-없음}
    sys 그룹 멤버: ${SYS_MEMBERS:-없음}"
        fi

        DT="$DETAILS"

    output_checkpoint "$CODE" "$CAT" "$NAME" "$IMP" "$STD" "$RES" "$DESC" "$DT"
}

check09() {
    local CODE="U-09"
    local CAT="계정관리"
    local NAME="계정이 존재하지 않는 GID 금지"
    local IMP="하"
    local STD="시스템 관리나 운용에 불필요한 그룹이 제거된 경우"
    local RES=""
    local DESC=""
    local DT=""

    # 사용 중인 GID 목록 (passwd 파일의 기본 GID)
    typeset USED_GIDS=""
    USED_GIDS=$(cut -d: -f4 /etc/passwd 2>/dev/null | sort -u)

    # 사용되지 않는 그룹 확인 (HP-UX: GID >= 100, 시스템 그룹 제외)
    typeset UNUSED_GROUPS=""
    while IFS=: read -r name pass gid members; do
        if is_number "$gid" && [ "$gid" -ge 100 ]; then
            if [ -z "$members" ]; then
                typeset IS_USED="false"
                for used_gid in $USED_GIDS; do
                    if [ "$gid" = "$used_gid" ]; then
                        IS_USED="true"
                        break
                    fi
                done
                if [ "$IS_USED" = "false" ]; then
                    UNUSED_GROUPS="${UNUSED_GROUPS}${name}(GID:$gid) "
                fi
            fi
        fi
    done < /etc/group

    if [ -z "$UNUSED_GROUPS" ]; then
        RES="Y"
        DESC="불필요한 그룹이 존재하지 않음"
        DT="사용되지 않는 그룹: 없음"
    else
        RES="M"
        DESC="사용되지 않는 그룹 수동 확인 필요"
        DT="확인 필요 그룹: $UNUSED_GROUPS"
    fi

    output_checkpoint "$CODE" "$CAT" "$NAME" "$IMP" "$STD" "$RES" "$DESC" "$DT"
}

check10() {
    local CODE="U-10"
    local CAT="계정관리"
    local NAME="동일한 UID 금지"
    local IMP="중"
    local STD="동일한 UID로 설정된 사용자 계정이 존재하지 않는 경우"
    local RES=""
    local DESC=""
    local DT=""

        # 중복 UID 확인
        typeset DUP_UIDS=""
        DUP_UIDS=$(awk -F: '{print $3}' /etc/passwd 2>/dev/null | sort | uniq -d)

        if [ -z "$DUP_UIDS" ]; then
            RES="Y"
            DESC="동일한 UID를 가진 계정이 없음"
            DT="중복 UID: 없음"
        else
            typeset DUP_ACCOUNTS=""
            for uid in $DUP_UIDS; do
                typeset accounts=""
                accounts=$(awk -F: -v uid="$uid" '$3 == uid {print $1}' /etc/passwd 2>/dev/null | tr '\n' ',' | sed 's/,$//')
                DUP_ACCOUNTS="${DUP_ACCOUNTS}UID=$uid: $accounts
    "
            done
            RES="N"
            DESC="동일한 UID를 가진 계정이 존재함"
            DT="$DUP_ACCOUNTS"
        fi

    output_checkpoint "$CODE" "$CAT" "$NAME" "$IMP" "$STD" "$RES" "$DESC" "$DT"
}

check11() {
    local CODE="U-11"
    local CAT="계정관리"
    local NAME="사용자 shell 점검"
    local IMP="하"
    local STD="로그인이 필요하지 않은 계정에 /bin/false(/sbin/nologin) 쉘이 부여된 경우"
    local RES=""
    local DESC=""
    local DT=""

    # 로그인이 불필요한 계정 목록
    typeset NOLOGIN_ACCOUNTS="daemon bin sys adm listen nobody nobody4 noaccess diag operator games gopher"
    typeset VULNERABLE_ACCOUNTS=""

    for acc in $NOLOGIN_ACCOUNTS; do
        typeset shell=""
        shell=$(grep "^${acc}:" /etc/passwd 2>/dev/null | cut -d: -f7)
        if [ -n "$shell" ]; then
            case "$shell" in
                */nologin|*/false) ;;
                *) VULNERABLE_ACCOUNTS="${VULNERABLE_ACCOUNTS}${acc}($shell) " ;;
            esac
        fi
    done

    if [ -z "$VULNERABLE_ACCOUNTS" ]; then
        RES="Y"
        DESC="로그인 불필요 계정에 적절한 쉘 설정됨"
        DT="취약 계정: 없음"
    else
        RES="N"
        DESC="로그인 불필요 계정에 쉘이 부여됨"
        DT="취약 계정: $VULNERABLE_ACCOUNTS"
    fi

    output_checkpoint "$CODE" "$CAT" "$NAME" "$IMP" "$STD" "$RES" "$DESC" "$DT"
}

check12() {
    local CODE="U-12"
    local CAT="계정관리"
    local NAME="세션 종료 시간 설정"
    local IMP="하"
    local STD="Session Timeout이 600초(10분) 이하로 설정된 경우"
    local RES=""
    local DESC=""
    local DT=""

    typeset TMOUT_VALUE=""
    typeset DETAILS=""

    # /etc/profile 확인 (sh, ksh, bash)
    if [ -f /etc/profile ]; then
        typeset found=""
        found=$(grep -E "^[[:space:]]*(export[[:space:]]+)?TMOUT=" /etc/profile 2>/dev/null | head -1)
        if [ -n "$found" ]; then
            TMOUT_VALUE=$(echo "$found" | sed 's/.*TMOUT=//' | tr -d ' ' | cut -d';' -f1)
            DETAILS="/etc/profile TMOUT=$TMOUT_VALUE"
        fi
    fi

    # $HOME/.profile 확인
    if [ -z "$TMOUT_VALUE" ] && [ -f /.profile ]; then
        typeset found=""
        found=$(grep -E "^[[:space:]]*(export[[:space:]]+)?TMOUT=" /.profile 2>/dev/null | head -1)
        if [ -n "$found" ]; then
            TMOUT_VALUE=$(echo "$found" | sed 's/.*TMOUT=//' | tr -d ' ' | cut -d';' -f1)
            DETAILS="/.profile TMOUT=$TMOUT_VALUE"
        fi
    fi

    # /etc/csh.login 또는 /etc/csh.cshrc 확인 (csh용 autologout)
    if [ -z "$TMOUT_VALUE" ]; then
        for csh_file in /etc/csh.login /etc/csh.cshrc; do
            if [ -f "$csh_file" ]; then
                typeset autologout=""
                autologout=$(grep "^set autologout" "$csh_file" 2>/dev/null | head -1)
                if [ -n "$autologout" ]; then
                    typeset minutes=""
                    minutes=$(echo "$autologout" | sed 's/.*autologout=//' | tr -d ' ')
                    if is_number "$minutes"; then
                        TMOUT_VALUE=$((minutes * 60))
                        DETAILS="$csh_file autologout=${minutes}min (${TMOUT_VALUE}sec)"
                    fi
                    break
                fi
            fi
        done
    fi

    # 판단
    if [ -z "$TMOUT_VALUE" ]; then
        RES="N"
        DESC="세션 종료 시간이 설정되지 않음"
        DT="TMOUT: not set"
    elif is_number "$TMOUT_VALUE" && [ "$TMOUT_VALUE" -le 600 ]; then
        RES="Y"
        DESC="세션 종료 시간이 적절히 설정됨"
        DT="$DETAILS (기준: 600초 이하)"
    else
        RES="N"
        DESC="세션 종료 시간이 600초 초과"
        DT="$DETAILS (기준: 600초 이하)"
    fi

    output_checkpoint "$CODE" "$CAT" "$NAME" "$IMP" "$STD" "$RES" "$DESC" "$DT"
}

check13() {
    local CODE="U-13"
    local CAT="계정관리"
    local NAME="안전한 비밀번호 암호화 알고리즘 사용"
    local IMP="중"
    local STD="SHA-2 이상의 안전한 비밀번호 암호화 알고리즘을 사용하는 경우"
    local RES=""
    local DESC=""
    local DT=""

        typeset DETAILS=""
        typeset HAS_WEAK="false"

        # HP-UX: /etc/default/security의 CRYPT_DEFAULT 확인
        typeset CRYPT_DEFAULT=""

        if [ -f "$SECURITY_CONFIG" ]; then
            CRYPT_DEFAULT=$(grep "^CRYPT_DEFAULT" "$SECURITY_CONFIG" 2>/dev/null | cut -d'=' -f2 | tr -d ' ')
            DETAILS="CRYPT_DEFAULT: ${CRYPT_DEFAULT:-not set}"

            case "$CRYPT_DEFAULT" in
                1) DETAILS="${DETAILS} (MD5 - 취약)"; HAS_WEAK="true" ;;
                2) DETAILS="${DETAILS} (Blowfish)" ;;
                5) DETAILS="${DETAILS} (SHA-256)" ;;
                6) DETAILS="${DETAILS} (SHA-512)" ;;
                "") DETAILS="${DETAILS} (기본값 - 확인필요)" ;;
            esac
        else
            DETAILS="$SECURITY_CONFIG: 파일 없음"
        fi

        # /etc/shadow에서 암호화 알고리즘 확인 (존재하는 경우)
        if [ -f /etc/shadow ]; then
            typeset ENCRYPT_TYPES=""
            ENCRYPT_TYPES=$(awk -F: '$2 ~ /^\$/ {print substr($2,1,3)}' /etc/shadow 2>/dev/null | sort | uniq)

            typeset ALGO_INFO=""
            for type in $ENCRYPT_TYPES; do
                case "$type" in
                    '$1$') ALGO_INFO="${ALGO_INFO}MD5(취약) "; HAS_WEAK="true" ;;
                    '$2$') ALGO_INFO="${ALGO_INFO}Blowfish " ;;
                    '$5$') ALGO_INFO="${ALGO_INFO}SHA-256 " ;;
                    '$6$') ALGO_INFO="${ALGO_INFO}SHA-512 " ;;
                    *) ALGO_INFO="${ALGO_INFO}${type} " ;;
                esac
            done
            DETAILS="${DETAILS}
    사용 중인 알고리즘: ${ALGO_INFO:-확인불가}"
        fi

        # Trusted Mode의 경우 /tcb/files/auth 확인
        if [ -d /tcb/files/auth ]; then
            DETAILS="${DETAILS}
    Trusted Mode: 활성화됨 (TCB 기반 비밀번호 관리)"
        fi

        if [ "$HAS_WEAK" = "true" ]; then
            RES="N"
            DESC="취약한 암호화 알고리즘 사용 중"
        elif [ -z "$CRYPT_DEFAULT" ] && [ ! -f /etc/shadow ] && [ ! -d /tcb/files/auth ]; then
            RES="N"
            DESC="암호화 알고리즘 설정 확인 불가"
        else
            RES="Y"
            DESC="안전한 암호화 알고리즘 사용 중"
        fi

        DT="$DETAILS"

    output_checkpoint "$CODE" "$CAT" "$NAME" "$IMP" "$STD" "$RES" "$DESC" "$DT"
}

check14() {
    local CODE="U-14"
    local CAT="파일및디렉토리관리"
    local NAME="root 홈, 패스 디렉터리 권한 및 패스 설정"
    local IMP="상"
    local STD="PATH 환경변수에 “.” 이 맨 앞이나 중간에 포함되지 않은 경우"
    local RES=""
    local DESC=""
    local DT=""

        # PATH에 . 또는 :: 포함 여부 확인
        typeset ROOT_PATH=""
        ROOT_PATH=$(su - root -c 'echo $PATH' 2>/dev/null)
        typeset HAS_DOT="false"

        # PATH에 . 이 맨 앞이나 중간에 포함되어 있는지 확인
        case "$ROOT_PATH" in
            .:*|*:.:*|*::*) HAS_DOT="true" ;;
        esac

        # root 홈 디렉토리 확인
        typeset ROOT_HOME=""
        ROOT_HOME=$(grep "^root:" /etc/passwd 2>/dev/null | cut -d: -f6)
        typeset ROOT_HOME_PERM=""
        if [ -d "$ROOT_HOME" ]; then
            ROOT_HOME_PERM=$(get_file_perm "$ROOT_HOME" 2>/dev/null)
        fi

        if [ "$HAS_DOT" = "true" ]; then
            RES="N"
            DESC="PATH에 . 이 포함되어 있음"
            DT="PATH: $ROOT_PATH
    root 홈($ROOT_HOME) 권한: ${ROOT_HOME_PERM:-확인불가}"
        elif [ -n "$ROOT_HOME_PERM" ] && is_number "$ROOT_HOME_PERM" && [ "$ROOT_HOME_PERM" -gt 750 ]; then
            RES="N"
            DESC="root 홈 디렉토리 권한이 과도함"
            DT="root 홈($ROOT_HOME) 권한: $ROOT_HOME_PERM (기준: 750 이하)"
        else
            RES="Y"
            DESC="PATH 및 root 홈 디렉토리 설정 양호"
            DT="PATH: ${ROOT_PATH:-확인불가}
    root 홈($ROOT_HOME) 권한: ${ROOT_HOME_PERM:-확인불가}"
        fi

    output_checkpoint "$CODE" "$CAT" "$NAME" "$IMP" "$STD" "$RES" "$DESC" "$DT"
}

check15() {
    local CODE="U-15"
    local CAT="파일및디렉토리관리"
    local NAME="파일 및 디렉터리 소유자 설정"
    local IMP="상"
    local STD="소유자가 존재하지 않는 파일 및 디렉터리가 존재하지 않는 경우"
    local RES=""
    local DESC=""
    local DT=""

        # 소유자가 없는 파일 확인 (주요 디렉토리만)
        typeset NOOWNER=""
        NOOWNER=$(find /etc /var /tmp -xdev \( -nouser -o -nogroup \) 2>/dev/null | head -10)

        if [ -z "$NOOWNER" ]; then
            RES="Y"
            DESC="소유자가 없는 파일이 존재하지 않음"
            DT="소유자 없는 파일: 없음"
        else
            typeset NOOWNER_CNT=""
            NOOWNER_CNT=$(find /etc /var /tmp -xdev \( -nouser -o -nogroup \) 2>/dev/null | wc -l | tr -d ' ')
            RES="N"
            DESC="소유자가 없는 파일이 존재함 (${NOOWNER_CNT}건)"
            DT="소유자 없는 파일 (상위 10건):
    $NOOWNER"
        fi

    output_checkpoint "$CODE" "$CAT" "$NAME" "$IMP" "$STD" "$RES" "$DESC" "$DT"
}

check16() {
    local CODE="U-16"
    local CAT="파일및디렉토리관리"
    local NAME="/etc/passwd 파일 소유자 및 권한 설정"
    local IMP="상"
    local STD="/etc/passwd 파일의 소유자가 root이고, 권한이 644 이하인 경우"
    local RES=""
    local DESC=""
    local DT=""

        typeset TARGET="/etc/passwd"

        if [ ! -f "$TARGET" ]; then
            RES="N/A"
            DESC="파일이 존재하지 않음"
            DT="파일: $TARGET (없음)"
        else
            typeset PERM=""
            typeset OWNER=""
            PERM=$(get_file_perm "$TARGET" 2>/dev/null)
            OWNER=$(get_file_owner "$TARGET" 2>/dev/null)

            if [ "$OWNER" = "root" ] && is_number "$PERM" && [ "$PERM" -le 644 ]; then
                RES="Y"
                DESC="파일 권한이 적절히 설정됨"
            else
                RES="N"
                DESC="파일 권한이 부적절함"
            fi
            DT="파일: $TARGET
    소유자: $OWNER
    권한: $PERM"
        fi

    output_checkpoint "$CODE" "$CAT" "$NAME" "$IMP" "$STD" "$RES" "$DESC" "$DT"
}

check17() {
    local CODE="U-17"
    local CAT="파일및디렉토리관리"
    local NAME="시스템 시작 스크립트 권한 설정"
    local IMP="상"
    local STD="시스템 시작 스크립트 파일의 소유자가 root이고, 일반 사용자의 쓰기 권한이 제거된 경우"
    local RES=""
    local DESC=""
    local DT=""

        typeset VULNERABLE=""
        # HP-UX 시스템 시작 스크립트 경로: /sbin/rc*.d/ 및 /sbin/init.d
        typeset TARGETS="/sbin/rc0.d /sbin/rc1.d /sbin/rc2.d /sbin/rc3.d /sbin/init.d"
        typeset CHECKED_LIST=""

        for target in $TARGETS; do
            if [ -d "$target" ]; then
                # 디렉토리 자체의 권한 확인
                typeset dir_perm=""
                typeset dir_owner=""
                dir_perm=$(get_file_perm "$target" 2>/dev/null)
                dir_owner=$(get_file_owner "$target" 2>/dev/null)
                CHECKED_LIST="${CHECKED_LIST}  - ${target} (${dir_owner}:${dir_perm})
    "

                # 디렉토리 내 스크립트 파일 확인
                for script in "$target"/*; do
                    if [ -f "$script" ] || [ -L "$script" ]; then
                        typeset real_script="$script"
                        if [ -L "$script" ]; then
                            real_script=$(ls -l "$script" 2>/dev/null | awk '{print $NF}')
                            if [ ! -f "$real_script" ]; then
                                continue
                            fi
                        fi

                        typeset perm=""
                        typeset owner=""
                        perm=$(get_file_perm "$real_script" 2>/dev/null)
                        owner=$(get_file_owner "$real_script" 2>/dev/null)

                        # other 쓰기 권한(2) 여부 확인
                        if [ -n "$perm" ]; then
                            typeset other_perm=$((perm % 10))
                            if [ "$owner" != "root" ] || [ $((other_perm & 2)) -ne 0 ]; then
                                VULNERABLE="${VULNERABLE}${script}(${owner}:${perm}) "
                            fi
                        fi
                    fi
                done
            fi
        done

        if [ -z "$CHECKED_LIST" ]; then
            RES="N/A"
            DESC="시스템 시작 스크립트 디렉토리가 존재하지 않음"
            DT="검사 대상 디렉토리 없음"
        elif [ -z "$VULNERABLE" ]; then
            RES="Y"
            DESC="시스템 시작 스크립트 권한 양호"
            DT="[검사 대상]
    ${CHECKED_LIST}
    [취약 파일]
    없음"
        else
            RES="N"
            DESC="시스템 시작 스크립트 권한 부적절"
            DT="[검사 대상]
    ${CHECKED_LIST}
    [취약 파일]
    $VULNERABLE"
        fi

    output_checkpoint "$CODE" "$CAT" "$NAME" "$IMP" "$STD" "$RES" "$DESC" "$DT"
}

check18() {
    local CODE="U-18"
    local CAT="파일및디렉토리관리"
    local NAME="/etc/shadow 파일 소유자 및 권한 설정"
    local IMP="상"
    local STD="/etc/shadow 파일의 소유자가 root이고, 권한이 400 이하인 경우"
    local RES=""
    local DESC=""
    local DT=""

        # HP-UX: /etc/shadow 또는 Trusted Mode의 /tcb/files/auth
        typeset TARGET=""

        if [ -f /etc/shadow ]; then
            TARGET="/etc/shadow"
        elif [ -d /tcb/files/auth ]; then
            TARGET="/tcb/files/auth"
        fi

        if [ -z "$TARGET" ]; then
            RES="N/A"
            DESC="비밀번호 파일이 존재하지 않음"
            DT="/etc/shadow: 없음
    /tcb/files/auth: 없음"
        elif [ -f "$TARGET" ]; then
            typeset PERM=""
            typeset OWNER=""
            PERM=$(get_file_perm "$TARGET")
            OWNER=$(get_file_owner "$TARGET")

            if [ "$OWNER" = "root" ] && [ "$PERM" -le 400 ] 2>/dev/null; then
                RES="Y"
                DESC="파일 권한이 적절히 설정됨"
            else
                RES="N"
                DESC="파일 권한이 부적절함"
            fi
            DT="파일: $TARGET
    소유자: $OWNER
    권한: $PERM (기준: 400 이하)"
        elif [ -d "$TARGET" ]; then
            typeset PERM=""
            typeset OWNER=""
            PERM=$(get_file_perm "$TARGET")
            OWNER=$(get_file_owner "$TARGET")

            if [ "$OWNER" = "root" ] && [ "$PERM" -le 700 ] 2>/dev/null; then
                RES="Y"
                DESC="디렉토리 권한이 적절히 설정됨"
            else
                RES="N"
                DESC="디렉토리 권한이 부적절함"
            fi
            DT="디렉토리: $TARGET
    소유자: $OWNER
    권한: $PERM (기준: 700 이하)"
        fi

    output_checkpoint "$CODE" "$CAT" "$NAME" "$IMP" "$STD" "$RES" "$DESC" "$DT"
}

check19() {
    local CODE="U-19"
    local CAT="파일및디렉토리관리"
    local NAME="/etc/hosts 파일 소유자 및 권한 설정"
    local IMP="상"
    local STD="/etc/hosts 파일의 소유자가 root이고, 권한이 644 이하인 경우"
    local RES=""
    local DESC=""
    local DT=""

        typeset TARGET="/etc/hosts"

        if [ ! -f "$TARGET" ]; then
            RES="N/A"
            DESC="파일이 존재하지 않음"
            DT="파일: $TARGET (없음)"
        else
            typeset PERM=""
            typeset OWNER=""
            PERM=$(get_file_perm "$TARGET")
            OWNER=$(get_file_owner "$TARGET")

            if [ "$OWNER" = "root" ] && [ "$PERM" -le 644 ] 2>/dev/null; then
                RES="Y"
                DESC="파일 권한이 적절히 설정됨"
            else
                RES="N"
                DESC="파일 권한이 부적절함"
            fi
            DT="파일: $TARGET
    소유자: $OWNER
    권한: $PERM (기준: 644 이하)"
        fi

    output_checkpoint "$CODE" "$CAT" "$NAME" "$IMP" "$STD" "$RES" "$DESC" "$DT"
}

check20() {
    local CODE="U-20"
    local CAT="파일및디렉토리관리"
    local NAME="/etc/(x)inetd.conf 파일 소유자 및 권한 설정"
    local IMP="상"
    local STD="/etc/(x)inetd.conf 파일의 소유자가 root이고, 권한이 600 이하인 경우"
    local RES=""
    local DESC=""
    local DT=""

        # HP-UX는 주로 inetd 사용
        typeset TARGET="/etc/inetd.conf"
        typeset FOUND="false"
        typeset VULNERABLE=""
        typeset DETAILS=""

        if [ -f "$TARGET" ]; then
            FOUND="true"
            typeset perm=""
            typeset owner=""
            perm=$(get_file_perm "$TARGET")
            owner=$(get_file_owner "$TARGET")
            DETAILS="${DETAILS}${TARGET}: ${owner}:${perm}
    "
            if [ "$owner" != "root" ] || [ "$perm" -gt 600 ] 2>/dev/null; then
                VULNERABLE="${VULNERABLE}${TARGET} "
            fi
        fi

        if [ "$FOUND" = "false" ]; then
            RES="N/A"
            DESC="inetd 설정 파일이 존재하지 않음"
            DT="inetd.conf: 미사용"
        elif [ -z "$VULNERABLE" ]; then
            RES="Y"
            DESC="파일 권한이 적절히 설정됨"
            DT="$DETAILS"
        else
            RES="N"
            DESC="파일 권한이 부적절함"
            DT="${DETAILS}취약 파일: $VULNERABLE"
        fi

    output_checkpoint "$CODE" "$CAT" "$NAME" "$IMP" "$STD" "$RES" "$DESC" "$DT"
}

check21() {
    local CODE="U-21"
    local CAT="파일및디렉토리관리"
    local NAME="/etc/(r)syslog.conf 파일 소유자 및 권한 설정"
    local IMP="상"
    local STD="/etc/(r)syslog.conf 파일의 소유자가 root(또는 bin, sys)이고, 권한이 640 이하인 경우"
    local RES=""
    local DESC=""
    local DT=""

        # HP-UX는 주로 /etc/syslog.conf 사용
        typeset TARGETS="/etc/syslog.conf /etc/rsyslog.conf"
        typeset FOUND="false"
        typeset VULNERABLE=""
        typeset DETAILS=""

        for target in $TARGETS; do
            if [ -f "$target" ]; then
                FOUND="true"
                typeset perm=""
                typeset owner=""
                perm=$(get_file_perm "$target")
                owner=$(get_file_owner "$target")
                DETAILS="${DETAILS}${target}: ${owner}:${perm}
    "
                # 소유자가 root, bin, sys 중 하나이고 권한이 640 이하인지 확인
                typeset owner_ok="false"
                case "$owner" in
                    root|bin|sys) owner_ok="true" ;;
                esac

                if [ "$owner_ok" = "false" ] || [ "$perm" -gt 640 ] 2>/dev/null; then
                    VULNERABLE="${VULNERABLE}${target} "
                fi
            fi
        done

        if [ "$FOUND" = "false" ]; then
            RES="N/A"
            DESC="syslog 설정 파일이 존재하지 않음"
            DT="(r)syslog.conf: 없음"
        elif [ -z "$VULNERABLE" ]; then
            RES="Y"
            DESC="파일 권한이 적절히 설정됨"
            DT="$DETAILS"
        else
            RES="N"
            DESC="파일 권한이 부적절함"
            DT="${DETAILS}취약 파일: $VULNERABLE"
        fi

    output_checkpoint "$CODE" "$CAT" "$NAME" "$IMP" "$STD" "$RES" "$DESC" "$DT"
}

check22() {
    local CODE="U-22"
    local CAT="파일및디렉토리관리"
    local NAME="/etc/services 파일 소유자 및 권한 설정"
    local IMP="상"
    local STD="/etc/services 파일의 소유자가 root(또는 bin, sys)이고, 권한이 644 이하인 경우"
    local RES=""
    local DESC=""
    local DT=""

        typeset TARGET="/etc/services"

        if [ ! -f "$TARGET" ]; then
            RES="N/A"
            DESC="파일이 존재하지 않음"
            DT="파일: $TARGET (없음)"
        else
            typeset PERM=""
            typeset OWNER=""
            PERM=$(get_file_perm "$TARGET")
            OWNER=$(get_file_owner "$TARGET")

            # 소유자가 root, bin, sys 중 하나이고 권한이 644 이하인지 확인
            typeset owner_ok="false"
            case "$OWNER" in
                root|bin|sys) owner_ok="true" ;;
            esac

            if [ "$owner_ok" = "true" ] && [ "$PERM" -le 644 ] 2>/dev/null; then
                RES="Y"
                DESC="파일 권한이 적절히 설정됨"
            else
                RES="N"
                DESC="파일 권한이 부적절함"
            fi
            DT="파일: $TARGET
    소유자: $OWNER
    권한: $PERM (기준: 644 이하)"
        fi

    output_checkpoint "$CODE" "$CAT" "$NAME" "$IMP" "$STD" "$RES" "$DESC" "$DT"
}

check23() {
    local CODE="U-23"
    local CAT="파일및디렉토리관리"
    local NAME="SUID, SGID, Sticky bit 설정 파일 점검"
    local IMP="상"
    local STD="주요 실행 파일의 권한에 SUID와 SGID에 대한 설정이 부여되어 있지 않은 경우"
    local RES=""
    local DESC=""
    local DT=""

        # SUID/SGID 파일 검색 (주요 디렉토리만)
        typeset SUID_FILES=""
        SUID_FILES=$(find /usr /bin /sbin /opt -type f \( -perm -4000 -o -perm -2000 \) 2>/dev/null | head -20)
        typeset COUNT=0
        if [ -n "$SUID_FILES" ]; then
            COUNT=$(echo "$SUID_FILES" | wc -l | tr -d ' ')
        fi

        RES="M"
        DESC="SUID/SGID 파일 수동 확인 필요 (${COUNT}개 발견)"
        DT="[검사 대상]
      /usr /bin /sbin /opt

    [SUID/SGID 파일 목록] (상위 20개)
    $SUID_FILES"

    output_checkpoint "$CODE" "$CAT" "$NAME" "$IMP" "$STD" "$RES" "$DESC" "$DT"
}

check24() {
    local CODE="U-24"
    local CAT="파일및디렉토리관리"
    local NAME="사용자, 시스템 환경변수 파일 소유자 및 권한 설정"
    local IMP="상"
    local STD="홈 디렉터리 환경변수 파일 소유자가 root 또는 해당 계정으로 지정되어 있고, 홈 디렉터리 환경변수 파일에 root 계정과 소유자만 쓰기 권한이 부여된 경우"
    local RES=""
    local DESC=""
    local DT=""

        # HP-UX 환경변수 파일 목록
        typeset TARGETS="/etc/profile /etc/csh.login /etc/csh.cshrc /.profile /.cshrc /.kshrc"
        typeset VULNERABLE=""
        typeset DETAILS=""

        for target in $TARGETS; do
            if [ -f "$target" ]; then
                typeset perm=""
                typeset owner=""
                perm=$(get_file_perm "$target")
                owner=$(get_file_owner "$target")
                DETAILS="${DETAILS}  ${target}: ${owner}:${perm}
    "
                # other 쓰기 권한 확인
                typeset other_perm=$((perm % 10))
                if [ "$owner" != "root" ] || [ $((other_perm & 2)) -ne 0 ] 2>/dev/null; then
                    VULNERABLE="${VULNERABLE}${target} "
                fi
            fi
        done

        # 사용자 홈 디렉토리 환경변수 파일도 점검
        typeset ENV_FILES=".profile .kshrc .cshrc .bashrc .bash_profile .login .exrc .netrc"
        while IFS=: read -r user pass uid gid gecos home shell; do
            if [ "$uid" -ge 100 ] 2>/dev/null && [ -d "$home" ]; then
                for envfile in $ENV_FILES; do
                    typeset fpath="${home}/${envfile}"
                    if [ -f "$fpath" ]; then
                        typeset perm=""
                        typeset owner=""
                        perm=$(get_file_perm "$fpath")
                        owner=$(get_file_owner "$fpath")
                        # other 쓰기 권한 확인
                        typeset other_perm=$((perm % 10))
                        if [ "$owner" != "root" ] && [ "$owner" != "$user" ]; then
                            VULNERABLE="${VULNERABLE}${fpath} "
                        elif [ $((other_perm & 2)) -ne 0 ] 2>/dev/null; then
                            VULNERABLE="${VULNERABLE}${fpath} "
                        fi
                    fi
                done
            fi
        done < /etc/passwd

        if [ -z "$VULNERABLE" ]; then
            RES="Y"
            DESC="환경변수 파일 권한 양호"
            DT="[시스템 환경변수 파일]
    ${DETAILS:-  해당 파일 없음}"
        else
            RES="N"
            DESC="환경변수 파일 권한 부적절"
            DT="[시스템 환경변수 파일]
    ${DETAILS:-  해당 파일 없음}
    [취약 파일]
    $VULNERABLE"
        fi

    output_checkpoint "$CODE" "$CAT" "$NAME" "$IMP" "$STD" "$RES" "$DESC" "$DT"
}

check25() {
    local CODE="U-25"
    local CAT="파일및디렉토리관리"
    local NAME="world writable 파일 점검"
    local IMP="상"
    local STD="world writable 파일이 존재하지 않거나, 존재 시 설정 이유를 인지하고 있는 경우"
    local RES=""
    local DESC=""
    local DT=""

        # 검사 대상 디렉토리
        typeset SEARCH_DIRS="/etc /var"

        # world writable 파일 검색 (주요 디렉토리)
        typeset WW_FILES=""
        WW_FILES=$(find /etc /var -type f -perm -2 2>/dev/null | head -10)
        typeset WW_COUNT=0
        if [ -n "$WW_FILES" ]; then
            WW_COUNT=$(find /etc /var -type f -perm -2 2>/dev/null | wc -l | tr -d ' ')
        fi

        if [ -z "$WW_FILES" ]; then
            RES="Y"
            DESC="world writable 파일이 존재하지 않음"
            DT="[검사 대상 디렉토리]
      $SEARCH_DIRS

    [world writable 파일]
    없음"
        else
            RES="N"
            DESC="world writable 파일이 존재함 (${WW_COUNT}개)"
            DT="[검사 대상 디렉토리]
      $SEARCH_DIRS

    [world writable 파일] (최대 10개 표시)
    $WW_FILES"
        fi

    output_checkpoint "$CODE" "$CAT" "$NAME" "$IMP" "$STD" "$RES" "$DESC" "$DT"
}

check26() {
    local CODE="U-26"
    local CAT="파일및디렉토리관리"
    local NAME="/dev에 존재하지 않는 device 파일 점검"
    local IMP="상"
    local STD="/dev 디렉터리에 대한 파일 점검 후 존재하지 않는 device 파일을 제거한 경우"
    local RES=""
    local DESC=""
    local DT=""

        # /dev 디렉토리 내 일반 파일 검색 (device 파일이 아닌 것)
        typeset DEV_FILES=""
        DEV_FILES=$(find /dev -type f 2>/dev/null | head -10)
        typeset DEV_COUNT=0
        if [ -n "$DEV_FILES" ]; then
            DEV_COUNT=$(find /dev -type f 2>/dev/null | wc -l | tr -d ' ')
        fi

        if [ -z "$DEV_FILES" ]; then
            RES="Y"
            DESC="/dev에 일반 파일이 없음"
            DT="[검사 범위]
      /dev 디렉토리

    [비정상 파일]
    없음"
        else
            RES="N"
            DESC="/dev에 일반 파일 존재 (${DEV_COUNT}개)"
            DT="[검사 범위]
      /dev 디렉토리

    [비정상 파일] (최대 10개 표시)
    $DEV_FILES"
        fi

    output_checkpoint "$CODE" "$CAT" "$NAME" "$IMP" "$STD" "$RES" "$DESC" "$DT"
}

check27() {
    local CODE="U-27"
    local CAT="파일및디렉토리관리"
    local NAME="\$HOME/.rhosts, hosts.equiv 사용 금지"
    local IMP="상"
    local STD="rlogin, rsh, rexec 서비스를 사용하지 않거나, 사용 시 아래와 같은 설정이 적용된 경우 1. /etc/hosts.equiv 및 \$HOME/.rhosts 파일 소유자가 root 또는 해당 계정인 경우 2. /etc/hosts.equiv 및 \$HOME/.rhosts 파일 권한이 600 이하인 경우 3. /etc/hosts.equiv 및 \$HOME/.rhosts 파일 설정에 “+” 설정이 없는 경우"
    local RES=""
    local DESC=""
    local DT=""

        typeset VULNERABLE=""
        typeset DETAILS=""

        # r-command 서비스 실행 여부 확인
        typeset RCMD_RUNNING="false"
        if is_process_running "rlogind" || is_process_running "rshd" || is_process_running "rexecd"; then
            RCMD_RUNNING="true"
        fi

        # /etc/hosts.equiv 확인
        if [ -f /etc/hosts.equiv ]; then
            typeset perm=""
            typeset owner=""
            perm=$(get_file_perm /etc/hosts.equiv)
            owner=$(get_file_owner /etc/hosts.equiv)
            DETAILS="${DETAILS}/etc/hosts.equiv: ${owner}:${perm}
    "
            # + 설정 확인
            typeset PLUS_SET=""
            PLUS_SET=$(grep "^+" /etc/hosts.equiv 2>/dev/null)
            if [ -n "$PLUS_SET" ]; then
                DETAILS="${DETAILS}  + 설정 발견: 위험
    "
                VULNERABLE="${VULNERABLE}/etc/hosts.equiv(+설정) "
            fi
            if [ "$owner" != "root" ] || [ "$perm" -gt 600 ] 2>/dev/null; then
                VULNERABLE="${VULNERABLE}/etc/hosts.equiv(권한) "
            fi
        fi

        # 사용자 홈 디렉토리의 .rhosts 확인
        while IFS=: read -r user pass uid gid gecos home shell; do
            if [ -f "${home}/.rhosts" ] 2>/dev/null; then
                typeset perm=""
                typeset owner=""
                perm=$(get_file_perm "${home}/.rhosts")
                owner=$(get_file_owner "${home}/.rhosts")
                DETAILS="${DETAILS}${home}/.rhosts: ${owner}:${perm}
    "
                typeset PLUS_SET=""
                PLUS_SET=$(grep "^+" "${home}/.rhosts" 2>/dev/null)
                if [ -n "$PLUS_SET" ]; then
                    VULNERABLE="${VULNERABLE}${home}/.rhosts(+설정) "
                fi
                if [ "$owner" != "root" ] && [ "$owner" != "$user" ]; then
                    VULNERABLE="${VULNERABLE}${home}/.rhosts(소유자) "
                fi
                if [ "$perm" -gt 600 ] 2>/dev/null; then
                    VULNERABLE="${VULNERABLE}${home}/.rhosts(권한) "
                fi
            fi
        done < /etc/passwd

        if [ "$RCMD_RUNNING" = "false" ] && [ -z "$VULNERABLE" ]; then
            RES="Y"
            DESC="r-command 미사용, .rhosts/hosts.equiv 파일 양호"
            DT="r-command 서비스: 미실행
    ${DETAILS:-취약 파일: 없음}"
        elif [ -z "$VULNERABLE" ]; then
            RES="Y"
            DESC=".rhosts, hosts.equiv 파일 양호"
            DT="r-command 서비스: 실행중
    ${DETAILS:-취약 파일: 없음}"
        else
            RES="N"
            DESC=".rhosts, hosts.equiv 파일 취약"
            DT="r-command 서비스: $([ "$RCMD_RUNNING" = "true" ] && printf "실행중" || printf "미실행")
    $DETAILS
    [취약 항목]
    $VULNERABLE"
        fi

    output_checkpoint "$CODE" "$CAT" "$NAME" "$IMP" "$STD" "$RES" "$DESC" "$DT"
}

check28() {
    local CODE="U-28"
    local CAT="파일및디렉토리관리"
    local NAME="접속 IP 및 포트 제한"
    local IMP="상"
    local STD="접속을 허용할 특정 호스트에 대한 IP주소 및 포트 제한을 설정한 경우"
    local RES=""
    local DESC=""
    local DT=""

        typeset DETAILS=""
        typeset HAS_RESTRICTION="false"

        # HP-UX: /var/adm/inetd.sec 확인 (HP-UX 고유 접근제한)
        if [ -f /var/adm/inetd.sec ]; then
            typeset INETD_SEC=""
            INETD_SEC=$(grep -v "^#" /var/adm/inetd.sec 2>/dev/null | grep -v "^$" | head -5)
            if [ -n "$INETD_SEC" ]; then
                DETAILS="${DETAILS}[inetd.sec]
    $INETD_SEC
    "
                HAS_RESTRICTION="true"
            fi
        fi

        # TCP Wrapper: hosts.allow / hosts.deny 확인
        if [ -f /etc/hosts.allow ]; then
            typeset ALLOW_CONTENT=""
            ALLOW_CONTENT=$(grep -v "^#" /etc/hosts.allow 2>/dev/null | grep -v "^$" | head -5)
            if [ -n "$ALLOW_CONTENT" ]; then
                DETAILS="${DETAILS}[hosts.allow]
    $ALLOW_CONTENT
    "
                HAS_RESTRICTION="true"
            fi
        fi

        if [ -f /etc/hosts.deny ]; then
            typeset DENY_CONTENT=""
            DENY_CONTENT=$(grep -v "^#" /etc/hosts.deny 2>/dev/null | grep -v "^$" | head -5)
            if [ -n "$DENY_CONTENT" ]; then
                DETAILS="${DETAILS}[hosts.deny]
    $DENY_CONTENT
    "
                HAS_RESTRICTION="true"
            fi
        fi

        # IPFilter 확인
        if [ -f /etc/ipf/ipf.conf ]; then
            typeset IPF_RULES=""
            IPF_RULES=$(grep -v "^#" /etc/ipf/ipf.conf 2>/dev/null | grep -v "^$" | head -5)
            if [ -n "$IPF_RULES" ]; then
                DETAILS="${DETAILS}[IPFilter (ipf.conf)]
    $IPF_RULES
    "
                HAS_RESTRICTION="true"
            fi
        fi

        if [ "$HAS_RESTRICTION" = "true" ]; then
            RES="Y"
            DESC="접속 IP/포트 제한이 설정됨"
        else
            RES="N"
            DESC="접속 IP/포트 제한이 미설정"
        fi

        DT="${DETAILS:-접근제한 설정: 없음}"

    output_checkpoint "$CODE" "$CAT" "$NAME" "$IMP" "$STD" "$RES" "$DESC" "$DT"
}

check29() {
    local CODE="U-29"
    local CAT="파일및디렉토리관리"
    local NAME="hosts.lpd 파일 소유자 및 권한 설정"
    local IMP="하"
    local STD="/etc/hosts.lpd 파일이 존재하지 않거나, 불가피하게 사용 시 /etc/hosts.lpd 파일의 소유자가 root이고, 권한이 600 이하인 경우"
    local RES=""
    local DESC=""
    local DT=""

        typeset TARGET="/etc/hosts.lpd"

        if [ ! -f "$TARGET" ]; then
            RES="Y"
            DESC="파일이 존재하지 않음 (양호)"
            DT="파일: $TARGET (없음)"
        else
            typeset PERM=""
            typeset OWNER=""
            PERM=$(get_file_perm "$TARGET")
            OWNER=$(get_file_owner "$TARGET")

            if [ "$OWNER" = "root" ] && [ "$PERM" -le 600 ] 2>/dev/null; then
                RES="Y"
                DESC="파일 권한이 적절히 설정됨"
            else
                RES="N"
                DESC="파일 권한이 부적절함"
            fi
            DT="파일: $TARGET
    소유자: $OWNER
    권한: $PERM (기준: 600 이하)"
        fi

    output_checkpoint "$CODE" "$CAT" "$NAME" "$IMP" "$STD" "$RES" "$DESC" "$DT"
}

check30() {
    local CODE="U-30"
    local CAT="파일및디렉토리관리"
    local NAME="UMASK 설정 관리"
    local IMP="중"
    local STD="UMASK 값이 022 이상으로 설정된 경우"
    local RES=""
    local DESC=""
    local DT=""

        typeset UMASK_VALUE=""
        typeset DETAILS=""

        # /etc/profile 확인
        if [ -f /etc/profile ]; then
            UMASK_VALUE=$(grep -i "^umask" /etc/profile 2>/dev/null | awk '{print $2}' | head -1)
            if [ -n "$UMASK_VALUE" ]; then
                DETAILS="/etc/profile UMASK=$UMASK_VALUE"
            fi
        fi

        # HP-UX: /etc/default/security 확인
        if [ -z "$UMASK_VALUE" ] && [ -f /etc/default/security ]; then
            UMASK_VALUE=$(grep "^UMASK" /etc/default/security 2>/dev/null | cut -d'=' -f2 | tr -d ' ' | head -1)
            if [ -n "$UMASK_VALUE" ]; then
                DETAILS="/etc/default/security UMASK=$UMASK_VALUE"
            fi
        fi

        # 현재 umask
        typeset CURRENT_UMASK=""
        CURRENT_UMASK=$(umask 2>/dev/null)
        DETAILS="${DETAILS}
    현재 UMASK: $CURRENT_UMASK"

        # 판단 (022 이상 설정 여부)
        typeset IS_OK="false"
        case "$UMASK_VALUE" in
            022|027|077|0022|0027|0077) IS_OK="true" ;;
        esac
        case "$CURRENT_UMASK" in
            022|027|077|0022|0027|0077) IS_OK="true" ;;
        esac

        if [ "$IS_OK" = "true" ]; then
            RES="Y"
            DESC="UMASK가 적절히 설정됨"
        else
            RES="N"
            DESC="UMASK 설정이 부적절함"
        fi

        DT="$DETAILS"

    output_checkpoint "$CODE" "$CAT" "$NAME" "$IMP" "$STD" "$RES" "$DESC" "$DT"
}

check31() {
    local CODE="U-31"
    local CAT="파일및디렉토리관리"
    local NAME="홈디렉토리 소유자 및 권한 설정"
    local IMP="중"
    local STD="홈 디렉토리 소유자가 해당 계정이고, 타 사용자 쓰기 권한이 제거된 경우"
    local RES=""
    local DESC=""
    local DT=""

        typeset VULNERABLE=""
        typeset DETAILS=""

        while IFS=: read -r user pass uid gid gecos home shell; do
            # HP-UX: UID 100 이상인 사용자 대상 점검
            if [ "$uid" -ge 100 ] 2>/dev/null && [ -d "$home" ]; then
                typeset perm=""
                typeset owner=""
                perm=$(get_file_perm "$home")
                owner=$(get_file_owner "$home")
                # other 쓰기 권한(2) 여부 확인
                typeset other_perm=$((perm % 10))
                if [ "$owner" != "$user" ] || [ $((other_perm & 2)) -ne 0 ] 2>/dev/null; then
                    VULNERABLE="${VULNERABLE}${home}(${owner}:${perm}) "
                fi
                DETAILS="${DETAILS}  ${user}: ${home} (${owner}:${perm})
    "
            fi
        done < /etc/passwd

        if [ -z "$VULNERABLE" ]; then
            RES="Y"
            DESC="홈 디렉토리 권한 양호"
        else
            RES="N"
            DESC="홈 디렉토리 권한 부적절"
        fi
        DT="[홈 디렉토리 점검 결과]
    ${DETAILS}
    [취약 항목]
    ${VULNERABLE:-없음}"

    output_checkpoint "$CODE" "$CAT" "$NAME" "$IMP" "$STD" "$RES" "$DESC" "$DT"
}

check32() {
    local CODE="U-32"
    local CAT="파일및디렉토리관리"
    local NAME="홈 디렉토리로 지정한 디렉토리의 존재 관리"
    local IMP="중"
    local STD="홈 디렉토리가 존재하지 않는 계정이 발견되지 않는 경우"
    local RES=""
    local DESC=""
    local DT=""

        typeset MISSING=""
        typeset DETAILS=""

        while IFS=: read -r user pass uid gid gecos home shell; do
            # HP-UX: UID 100 이상인 사용자 대상 점검
            if [ "$uid" -ge 100 ] 2>/dev/null; then
                if [ ! -d "$home" ]; then
                    MISSING="${MISSING}  ${user}: ${home}
    "
                else
                    DETAILS="${DETAILS}  ${user}: ${home} (존재)
    "
                fi
            fi
        done < /etc/passwd

        if [ -z "$MISSING" ]; then
            RES="Y"
            DESC="모든 홈 디렉토리가 존재함"
            DT="[홈 디렉토리 점검 결과]
    ${DETAILS}
    [누락된 홈 디렉토리]
    없음"
        else
            RES="N"
            DESC="존재하지 않는 홈 디렉토리 있음"
            DT="[홈 디렉토리 점검 결과]
    ${DETAILS}
    [누락된 홈 디렉토리]
    $MISSING"
        fi

    output_checkpoint "$CODE" "$CAT" "$NAME" "$IMP" "$STD" "$RES" "$DESC" "$DT"
}

check33() {
    local CODE="U-33"
    local CAT="파일및디렉토리관리"
    local NAME="숨겨진 파일 및 디렉토리 검색 및 제거"
    local IMP="하"
    local STD="불필요하거나 의심스러운 숨겨진 파일 및 디렉토리를 제거한 경우"
    local RES=""
    local DESC=""
    local DT=""

        # 홈 디렉토리 및 주요 경로에서 숨김 파일 검색
        typeset SEARCH_DIRS="/home /root /tmp"
        typeset HIDDEN_FILES=""
        HIDDEN_FILES=$(find /home /root /tmp -name ".*" -not -name "." -not -name ".." -type f 2>/dev/null | head -20)
        typeset COUNT=0
        if [ -n "$HIDDEN_FILES" ]; then
            COUNT=$(echo "$HIDDEN_FILES" | wc -l | tr -d ' ')
        fi

        RES="M"
        DESC="숨김 파일 수동 확인 필요 (${COUNT}개 발견)"
        DT="[검사 대상 디렉토리]
      $SEARCH_DIRS

    [숨김 파일 목록] (상위 20개)
    ${HIDDEN_FILES:-없음}"

    output_checkpoint "$CODE" "$CAT" "$NAME" "$IMP" "$STD" "$RES" "$DESC" "$DT"
}

check34() {
    local CODE="U-34"
    local CAT="서비스관리"
    local NAME="Finger 서비스 비활성화"
    local IMP="상"
    local STD="Finger 서비스가 비활성화된 경우"
    local RES=""
    local DESC=""
    local DT=""

        typeset RUNNING="false"
        typeset DETAILS=""

        # fingerd 프로세스 확인
        if is_process_running "fingerd"; then
            RUNNING="true"
            DETAILS="fingerd 프로세스: 실행 중
    "
        fi

        # inetd.conf에서 finger 서비스 확인
        if [ -f /etc/inetd.conf ]; then
            typeset FINGER_CONF=""
            FINGER_CONF=$(grep -v "^#" /etc/inetd.conf 2>/dev/null | grep -i "finger")
            if [ -n "$FINGER_CONF" ]; then
                RUNNING="true"
                DETAILS="${DETAILS}inetd.conf finger: 활성화
    ${FINGER_CONF}
    "
            fi
        fi

        # 포트 79 확인 (netstat)
        if netstat -an 2>/dev/null | grep "\.79 " | grep -qi "LISTEN"; then
            RUNNING="true"
            DETAILS="${DETAILS}포트 79: LISTEN 상태
    "
        fi

        if [ "$RUNNING" = "true" ]; then
            RES="N"
            DESC="Finger 서비스가 활성화되어 있음"
        else
            RES="Y"
            DESC="Finger 서비스가 비활성화됨"
            DETAILS="fingerd: 미실행, inetd.conf: 비활성"
        fi

        DT="$DETAILS"

    output_checkpoint "$CODE" "$CAT" "$NAME" "$IMP" "$STD" "$RES" "$DESC" "$DT"
}

check35() {
    local CODE="U-35"
    local CAT="서비스관리"
    local NAME="공유 서비스에 대한 익명 접근 제한 설정"
    local IMP="상"
    local STD="공유 서비스에 대해 익명 접근을 제한한 경우"
    local RES=""
    local DESC=""
    local DT=""

        typeset VULNERABLE="false"
        typeset DETAILS=""
        typeset SVC_FOUND="false"

        # FTP 익명 계정 확인
        typeset FTP_ANON=""
        FTP_ANON=$(grep -E "^ftp:|^anonymous:" /etc/passwd 2>/dev/null)
        if [ -n "$FTP_ANON" ]; then
            SVC_FOUND="true"
            VULNERABLE="true"
            DETAILS="${DETAILS}FTP 익명 계정 존재: ${FTP_ANON}
    "
        fi

        # vsFTPd 설정 확인
        if [ -f /etc/vsftpd.conf ]; then
            SVC_FOUND="true"
            typeset ANON_ENABLE=""
            ANON_ENABLE=$(grep -i "^anonymous_enable" /etc/vsftpd.conf 2>/dev/null | cut -d'=' -f2 | tr -d ' ')
            typeset ANON_LOWER=""
            ANON_LOWER=$(to_lower "$ANON_ENABLE")
            if [ "$ANON_LOWER" = "yes" ]; then
                VULNERABLE="true"
                DETAILS="${DETAILS}vsFTPd anonymous_enable=YES
    "
            else
                DETAILS="${DETAILS}vsFTPd anonymous_enable=${ANON_ENABLE:-not set}
    "
            fi
        fi

        # ProFTPd 설정 확인
        if [ -f /etc/proftpd.conf ]; then
            SVC_FOUND="true"
            typeset PROFTPD_ANON=""
            PROFTPD_ANON=$(grep -v "^#" /etc/proftpd.conf 2>/dev/null | grep -i "<Anonymous")
            if [ -n "$PROFTPD_ANON" ]; then
                VULNERABLE="true"
                DETAILS="${DETAILS}ProFTPd Anonymous 섹션 발견
    "
            fi
        fi

        # NFS exports 확인 (HP-UX: /etc/exports, /etc/dfs/dfstab)
        for nfs_file in /etc/exports /etc/dfs/dfstab; do
            if [ -f "$nfs_file" ]; then
                typeset NFS_CONTENT=""
                NFS_CONTENT=$(grep -v "^#" "$nfs_file" 2>/dev/null | grep -v "^$")
                if [ -n "$NFS_CONTENT" ]; then
                    SVC_FOUND="true"
                    DETAILS="${DETAILS}${nfs_file}:
    ${NFS_CONTENT}
    "
                    if echo "$NFS_CONTENT" | grep -q "anon="; then
                        typeset ANON_VAL=""
                        ANON_VAL=$(echo "$NFS_CONTENT" | grep "anon=" | sed 's/.*anon=//' | cut -d',' -f1 | cut -d' ' -f1)
                        if [ "$ANON_VAL" != "-1" ] 2>/dev/null; then
                            VULNERABLE="true"
                            DETAILS="${DETAILS}  anon=${ANON_VAL} (취약: -1이 아님)
    "
                        fi
                    fi
                fi
            fi
        done

        # Samba 확인 (HP-UX: /usr/lib/smb.conf)
        for smb_file in /usr/lib/smb.conf /etc/samba/smb.conf; do
            if [ -f "$smb_file" ]; then
                SVC_FOUND="true"
                typeset GUEST=""
                GUEST=$(grep -i "guest ok" "$smb_file" 2>/dev/null | grep -i "yes")
                if [ -n "$GUEST" ]; then
                    VULNERABLE="true"
                    DETAILS="${DETAILS}Samba(${smb_file}) guest ok = yes
    "
                fi
            fi
        done

        if [ "$SVC_FOUND" = "false" ]; then
            RES="N/A"
            DESC="공유 서비스가 설정되어 있지 않음"
            DT="FTP/NFS/Samba: 설정 없음"
        elif [ "$VULNERABLE" = "true" ]; then
            RES="N"
            DESC="공유 서비스에 익명 접근이 허용되어 있음"
        else
            RES="Y"
            DESC="공유 서비스에 익명 접근이 제한됨"
        fi

        DT="${DETAILS:-공유 서비스 설정: 양호}"

    output_checkpoint "$CODE" "$CAT" "$NAME" "$IMP" "$STD" "$RES" "$DESC" "$DT"
}

check36() {
    local CODE="U-36"
    local CAT="서비스관리"
    local NAME="r 계열 서비스 비활성화"
    local IMP="상"
    local STD="불필요한 r 계열 서비스가 비활성화된 경우"
    local RES=""
    local DESC=""
    local DT=""

        typeset RUNNING=""
        typeset DETAILS=""

        # r 계열 프로세스 확인 (HP-UX: remshd = rshd)
        for svc in rlogind rshd rexecd remshd; do
            if is_process_running "$svc"; then
                RUNNING="${RUNNING}${svc} "
            fi
        done

        # inetd.conf에서 r 계열 서비스 확인 (shell=rsh, login=rlogin, exec=rexec)
        if [ -f /etc/inetd.conf ]; then
            typeset R_SERVICES=""
            R_SERVICES=$(grep -v "^#" /etc/inetd.conf 2>/dev/null | grep -E "^(shell|login|exec)[[:space:]]")
            if [ -n "$R_SERVICES" ]; then
                DETAILS="inetd.conf r계열 서비스:
    ${R_SERVICES}
    "
                RUNNING="${RUNNING}inetd "
            fi
        fi

        # 포트 확인 (512=exec, 513=login, 514=shell)
        if netstat -an 2>/dev/null | grep -E "\.512 |\.513 |\.514 " | grep -qi "LISTEN"; then
            DETAILS="${DETAILS}r 계열 포트(512-514) LISTEN 상태
    "
        fi

        if [ -n "$RUNNING" ]; then
            RES="N"
            DESC="r 계열 서비스가 활성화되어 있음"
            DT="활성화: ${RUNNING}
    ${DETAILS}"
        else
            RES="Y"
            DESC="r 계열 서비스가 비활성화됨"
            DT="rlogind, rshd, rexecd: 미실행, inetd.conf: 비활성"
        fi

    output_checkpoint "$CODE" "$CAT" "$NAME" "$IMP" "$STD" "$RES" "$DESC" "$DT"
}

check37() {
    local CODE="U-37"
    local CAT="서비스관리"
    local NAME="crontab 설정파일 권한 설정 미흡"
    local IMP="상"
    local STD="crontab 및 at 명령어에 일반 사용자 실행 권한이 제거되어 있으며, cron 및 at 관련 파일 권한이 640 이하인 경우"
    local RES=""
    local DESC=""
    local DT=""

        typeset VULNERABLE=""
        typeset DETAILS=""

        # HP-UX crontab 명령어 권한 확인 (750 이하 권장)
        if [ -f /usr/bin/crontab ]; then
            typeset perm=""
            typeset owner=""
            perm=$(get_file_perm /usr/bin/crontab)
            owner=$(get_file_owner /usr/bin/crontab)
            DETAILS="${DETAILS}/usr/bin/crontab: ${owner}:${perm}
    "
            if [ "$owner" != "root" ]; then
                VULNERABLE="${VULNERABLE}/usr/bin/crontab "
            fi
        fi

        # HP-UX at 명령어 권한 확인 (750 이하 권장)
        if [ -f /usr/bin/at ]; then
            typeset perm=""
            typeset owner=""
            perm=$(get_file_perm /usr/bin/at)
            owner=$(get_file_owner /usr/bin/at)
            DETAILS="${DETAILS}/usr/bin/at: ${owner}:${perm}
    "
            if [ "$owner" != "root" ]; then
                VULNERABLE="${VULNERABLE}/usr/bin/at "
            fi
        fi

        # HP-UX cron 관련 설정 파일: /var/adm/cron/ (640 이하 권장)
        for file in /var/adm/cron/cron.allow /var/adm/cron/cron.deny /var/adm/cron/at.allow /var/adm/cron/at.deny; do
            if [ -f "$file" ]; then
                typeset perm=""
                typeset owner=""
                perm=$(get_file_perm "$file")
                owner=$(get_file_owner "$file")
                DETAILS="${DETAILS}${file}: ${owner}:${perm}
    "
                if [ "$owner" != "root" ]; then
                    VULNERABLE="${VULNERABLE}${file} "
                elif [ "$perm" -gt 640 ] 2>/dev/null; then
                    VULNERABLE="${VULNERABLE}${file} "
                fi
            fi
        done

        # cron 작업 목록 디렉터리 확인: /var/spool/cron/crontabs/
        if [ -d /var/spool/cron/crontabs ]; then
            typeset perm=""
            typeset owner=""
            perm=$(get_file_perm /var/spool/cron/crontabs)
            owner=$(get_file_owner /var/spool/cron/crontabs)
            DETAILS="${DETAILS}/var/spool/cron/crontabs: ${owner}:${perm}
    "
            if [ "$owner" != "root" ]; then
                VULNERABLE="${VULNERABLE}/var/spool/cron/crontabs "
            fi
        fi

        # at 작업 목록 디렉터리 확인: /var/spool/cron/atjobs/
        if [ -d /var/spool/cron/atjobs ]; then
            typeset perm=""
            typeset owner=""
            perm=$(get_file_perm /var/spool/cron/atjobs)
            owner=$(get_file_owner /var/spool/cron/atjobs)
            DETAILS="${DETAILS}/var/spool/cron/atjobs: ${owner}:${perm}
    "
            if [ "$owner" != "root" ]; then
                VULNERABLE="${VULNERABLE}/var/spool/cron/atjobs "
            fi
        fi

        if [ -z "$VULNERABLE" ]; then
            RES="Y"
            DESC="crontab 및 at 설정 파일 권한 양호"
        else
            RES="N"
            DESC="crontab 또는 at 설정 파일 권한 부적절"
        fi

        DT="${DETAILS}취약 파일: ${VULNERABLE:-없음}"

    output_checkpoint "$CODE" "$CAT" "$NAME" "$IMP" "$STD" "$RES" "$DESC" "$DT"
}

check38() {
    local CODE="U-38"
    local CAT="서비스관리"
    local NAME="DoS 공격에 취약한 서비스 비활성화"
    local IMP="상"
    local STD="DoS 공격에 취약한 서비스가 비활성화된 경우"
    local RES=""
    local DESC=""
    local DT=""

        typeset RUNNING=""
        typeset DETAILS=""

        # inetd.conf에서 DoS 취약 서비스 확인 (echo, discard, daytime, chargen)
        if [ -f /etc/inetd.conf ]; then
            typeset VULN_SERVICES=""
            VULN_SERVICES=$(grep -v "^#" /etc/inetd.conf 2>/dev/null | grep -E "^(echo|discard|daytime|chargen)[[:space:]]")
            if [ -n "$VULN_SERVICES" ]; then
                RUNNING="inetd "
                DETAILS="inetd.conf DoS 취약 서비스:
    ${VULN_SERVICES}
    "
            fi
        fi

        # 포트 확인 (echo:7, discard:9, daytime:13, chargen:19)
        typeset VULN_PORTS=""
        for port in 7 9 13 19; do
            if netstat -an 2>/dev/null | grep "\.${port} " | grep -qi "LISTEN"; then
                VULN_PORTS="${VULN_PORTS}${port} "
            fi
        done
        if [ -n "$VULN_PORTS" ]; then
            RUNNING="${RUNNING}ports "
            DETAILS="${DETAILS}LISTEN 상태 취약 포트: ${VULN_PORTS}
    "
        fi

        if [ -n "$RUNNING" ]; then
            RES="N"
            DESC="DoS 공격에 취약한 서비스가 활성화되어 있음"
        else
            RES="Y"
            DESC="DoS 공격에 취약한 서비스가 비활성화됨"
            DETAILS="echo, discard, daytime, chargen: 비활성"
        fi

        DT="$DETAILS"

    output_checkpoint "$CODE" "$CAT" "$NAME" "$IMP" "$STD" "$RES" "$DESC" "$DT"
}

check39() {
    local CODE="U-39"
    local CAT="서비스관리"
    local NAME="불필요한 NFS 서비스 비활성화"
    local IMP="상"
    local STD="불필요한 NFS 서비스 관련 데몬이 비활성화된 경우"
    local RES=""
    local DESC=""
    local DT=""

        typeset RUNNING="false"
        typeset DETAILS=""

        # NFS 관련 프로세스 확인 (nfsd, statd, lockd)
        for proc in nfsd statd lockd; do
            if is_process_running "$proc"; then
                RUNNING="true"
                DETAILS="${DETAILS}${proc}: 실행 중
    "
            fi
        done

        # HP-UX: /etc/rc.config.d/nfsconf의 NFS_SERVER 확인
        if [ -f /etc/rc.config.d/nfsconf ]; then
            typeset NFS_SERVER=""
            NFS_SERVER=$(grep "^NFS_SERVER" /etc/rc.config.d/nfsconf 2>/dev/null | cut -d'=' -f2)
            DETAILS="${DETAILS}NFS_SERVER=${NFS_SERVER:-not set}
    "
            if [ "$NFS_SERVER" = "1" ]; then
                RUNNING="true"
            fi
        fi

        # NFS 공유 파일 확인
        for nfs_file in /etc/exports /etc/dfs/dfstab; do
            if [ -f "$nfs_file" ] && [ -s "$nfs_file" ]; then
                typeset NFS_CONTENT=""
                NFS_CONTENT=$(grep -v "^#" "$nfs_file" 2>/dev/null | grep -v "^$" | head -5)
                if [ -n "$NFS_CONTENT" ]; then
                    DETAILS="${DETAILS}${nfs_file} 내용 존재
    "
                fi
            fi
        done

        # 포트 2049 확인
        if netstat -an 2>/dev/null | grep "\.2049 " | grep -qi "LISTEN"; then
            RUNNING="true"
            DETAILS="${DETAILS}포트 2049: LISTEN 상태
    "
        fi

        if [ "$RUNNING" = "true" ]; then
            RES="N"
            DESC="NFS 서비스가 활성화되어 있음"
        else
            RES="Y"
            DESC="NFS 서비스가 비활성화됨"
            DETAILS="NFS 관련 데몬: 미실행"
        fi

        DT="$DETAILS"

    output_checkpoint "$CODE" "$CAT" "$NAME" "$IMP" "$STD" "$RES" "$DESC" "$DT"
}

check40() {
    local CODE="U-40"
    local CAT="서비스관리"
    local NAME="NFS 접근 통제"
    local IMP="상"
    local STD="접근 통제가 설정되어 있으며 NFS 설정 파일 접근 권한이 644 이하인 경우"
    local RES=""
    local DESC=""
    local DT=""

        typeset VULNERABLE="false"
        typeset DETAILS=""
        typeset NFS_USED="false"

        # HP-UX: /etc/dfs/dfstab 및 /etc/exports 확인
        for nfs_file in /etc/dfs/dfstab /etc/exports; do
            if [ -f "$nfs_file" ]; then
                typeset perm=""
                typeset owner=""
                perm=$(get_file_perm "$nfs_file")
                owner=$(get_file_owner "$nfs_file")
                DETAILS="${DETAILS}${nfs_file}: ${owner}:${perm}
    "

                # 파일 내용 확인
                typeset CONTENT=""
                CONTENT=$(grep -v "^#" "$nfs_file" 2>/dev/null | grep -v "^$")
                if [ -n "$CONTENT" ]; then
                    NFS_USED="true"
                    DETAILS="${DETAILS}공유 설정:
    ${CONTENT}
    "

                    # 소유자 root 아님 또는 권한 644 초과
                    if [ "$owner" != "root" ]; then
                        VULNERABLE="true"
                        DETAILS="${DETAILS}  경고: 소유자가 root가 아님 (${owner})
    "
                    fi
                    if [ "$perm" -gt 644 ] 2>/dev/null; then
                        VULNERABLE="true"
                        DETAILS="${DETAILS}  경고: 권한 ${perm} > 644
    "
                    fi

                    # everyone(*) 접근 허용 확인
                    if echo "$CONTENT" | grep -q "\*"; then
                        VULNERABLE="true"
                        DETAILS="${DETAILS}  경고: 모든 호스트에 접근 허용(*)
    "
                    fi
                fi
            fi
        done

        if [ "$NFS_USED" = "false" ]; then
            RES="N/A"
            DESC="NFS 서비스를 사용하지 않음"
            DT="NFS 설정 파일: 없거나 비어있음"
        elif [ "$VULNERABLE" = "true" ]; then
            RES="N"
            DESC="NFS 접근 통제 설정 미흡"
        else
            RES="Y"
            DESC="NFS 접근 통제가 적절히 설정됨"
        fi

        DT="${DETAILS:-NFS 설정: 양호}"

    output_checkpoint "$CODE" "$CAT" "$NAME" "$IMP" "$STD" "$RES" "$DESC" "$DT"
}

check41() {
    local CODE="U-41"
    local CAT="서비스관리"
    local NAME="불필요한 automountd 제거"
    local IMP="상"
    local STD="automountd 서비스가 비활성화된 경우"
    local RES=""
    local DESC=""
    local DT=""

        typeset RUNNING="false"
        typeset DETAILS=""

        # automountd/autofs 프로세스 확인
        for proc in automountd autofs automount; do
            if is_process_running "$proc"; then
                RUNNING="true"
                DETAILS="${DETAILS}${proc}: 실행 중
    "
            fi
        done

        # HP-UX: /etc/rc.config.d/nfsconf의 AUTOFS 설정 확인
        if [ -f /etc/rc.config.d/nfsconf ]; then
            typeset AUTOFS_SET=""
            AUTOFS_SET=$(grep "^AUTOFS" /etc/rc.config.d/nfsconf 2>/dev/null | cut -d'=' -f2)
            DETAILS="${DETAILS}AUTOFS=${AUTOFS_SET:-not set}
    "
            if [ "$AUTOFS_SET" = "1" ]; then
                RUNNING="true"
            fi
        fi

        if [ "$RUNNING" = "true" ]; then
            RES="N"
            DESC="automountd 서비스가 활성화되어 있음"
        else
            RES="Y"
            DESC="automountd 서비스가 비활성화됨"
            DETAILS="automountd: 미실행, AUTOFS 비활성"
        fi

        DT="$DETAILS"

    output_checkpoint "$CODE" "$CAT" "$NAME" "$IMP" "$STD" "$RES" "$DESC" "$DT"
}

check42() {
    local CODE="U-42"
    local CAT="서비스관리"
    local NAME="불필요한 RPC 서비스 비활성화"
    local IMP="상"
    local STD="불필요한 RPC 서비스가 비활성화된 경우"
    local RES=""
    local DESC=""
    local DT=""

        typeset RUNNING=""
        typeset DETAILS=""

        # 불필요한 RPC 서비스 목록
        typeset RPC_SERVICES="rpc.cmsd rpc.ttdbserverd sadmind rusersd walld sprayd rstatd rpc.nisd rexd rpc.pcnfsd rpc.statd rpc.ypupdated rpc.rquotad kcms_server cachefsd"

        # inetd.conf에서 불필요한 RPC 서비스 확인
        if [ -f /etc/inetd.conf ]; then
            typeset RPC_FOUND=""
            RPC_FOUND=$(grep -v "^#" /etc/inetd.conf 2>/dev/null | grep -E "rpc\.|rusersd|walld|sprayd|rstatd|rexd|sadmind|cachefsd|kcms_server")
            if [ -n "$RPC_FOUND" ]; then
                RUNNING="${RUNNING}inetd "
                DETAILS="inetd.conf 불필요 RPC 서비스:
    ${RPC_FOUND}
    "
            fi
        fi

        # 프로세스 확인
        for svc in $RPC_SERVICES; do
            if is_process_running "$svc"; then
                RUNNING="${RUNNING}${svc} "
            fi
        done

        if [ -n "$RUNNING" ]; then
            RES="N"
            DESC="불필요한 RPC 서비스가 활성화되어 있음"
            DT="활성화: ${RUNNING}
    ${DETAILS}"
        else
            RES="Y"
            DESC="불필요한 RPC 서비스가 비활성화됨"
            DT="불필요 RPC 서비스: 미실행"
        fi

    output_checkpoint "$CODE" "$CAT" "$NAME" "$IMP" "$STD" "$RES" "$DESC" "$DT"
}

check43() {
    local CODE="U-43"
    local CAT="서비스관리"
    local NAME="NIS, NIS+ 점검"
    local IMP="상"
    local STD="NIS 서비스가 비활성화되어 있거나, 불가피하게 사용 시 NIS+ 서비스를 사용하는 경우"
    local RES=""
    local DESC=""
    local DT=""

        typeset RUNNING="false"
        typeset DETAILS=""

        # NIS 관련 프로세스 확인
        for proc in ypserv ypbind ypxfrd rpc.yppasswdd rpc.ypupdated rpc.nisd; do
            if is_process_running "$proc"; then
                RUNNING="true"
                DETAILS="${DETAILS}${proc}: 실행 중
    "
            fi
        done

        # HP-UX: /etc/rc.config.d/namesrvs의 NIS 설정 확인
        if [ -f /etc/rc.config.d/namesrvs ]; then
            typeset NIS_MASTER=""
            typeset NIS_SLAVE=""
            typeset NIS_CLIENT=""
            NIS_MASTER=$(grep "^NIS_MASTER_SERVER" /etc/rc.config.d/namesrvs 2>/dev/null | cut -d'=' -f2)
            NIS_SLAVE=$(grep "^NIS_SLAVE_SERVER" /etc/rc.config.d/namesrvs 2>/dev/null | cut -d'=' -f2)
            NIS_CLIENT=$(grep "^NIS_CLIENT" /etc/rc.config.d/namesrvs 2>/dev/null | cut -d'=' -f2)
            DETAILS="${DETAILS}NIS_MASTER_SERVER=${NIS_MASTER:-not set}
    NIS_SLAVE_SERVER=${NIS_SLAVE:-not set}
    NIS_CLIENT=${NIS_CLIENT:-not set}
    "
            if [ "$NIS_MASTER" = "1" ] || [ "$NIS_SLAVE" = "1" ] || [ "$NIS_CLIENT" = "1" ]; then
                RUNNING="true"
            fi
        fi

        # /etc/nsswitch.conf에서 NIS 사용 확인
        if [ -f /etc/nsswitch.conf ]; then
            typeset NIS_USE=""
            NIS_USE=$(grep -v "^#" /etc/nsswitch.conf 2>/dev/null | grep "nis")
            if [ -n "$NIS_USE" ]; then
                DETAILS="${DETAILS}nsswitch.conf NIS 참조:
    ${NIS_USE}
    "
            fi
        fi

        if [ "$RUNNING" = "true" ]; then
            RES="N"
            DESC="NIS 서비스가 활성화되어 있음"
        else
            RES="Y"
            DESC="NIS 서비스가 비활성화됨"
            if [ -z "$DETAILS" ]; then
                DETAILS="NIS 관련 데몬: 미실행"
            fi
        fi

        DT="$DETAILS"

    output_checkpoint "$CODE" "$CAT" "$NAME" "$IMP" "$STD" "$RES" "$DESC" "$DT"
}

check44() {
    local CODE="U-44"
    local CAT="서비스관리"
    local NAME="tftp, talk 서비스 비활성화"
    local IMP="상"
    local STD="tftp, talk, ntalk 서비스가 비활성화된 경우"
    local RES=""
    local DESC=""
    local DT=""

        typeset RUNNING=""
        typeset DETAILS=""

        # inetd.conf에서 tftp, talk, ntalk 서비스 확인
        if [ -f /etc/inetd.conf ]; then
            typeset VULN_SERVICES=""
            VULN_SERVICES=$(grep -v "^#" /etc/inetd.conf 2>/dev/null | grep -E "^(tftp|talk|ntalk)[[:space:]]")
            if [ -n "$VULN_SERVICES" ]; then
                RUNNING="${RUNNING}inetd "
                DETAILS="inetd.conf 서비스:
    ${VULN_SERVICES}
    "
            fi
        fi

        # 프로세스 확인
        for svc in tftpd in.tftpd talkd in.talkd ntalkd; do
            if is_process_running "$svc"; then
                RUNNING="${RUNNING}${svc} "
            fi
        done

        # 포트 확인 (tftp:69, talk:517, ntalk:518)
        for port in 69 517 518; do
            if netstat -an 2>/dev/null | grep "\.${port} " | grep -qi "LISTEN"; then
                RUNNING="${RUNNING}port${port} "
                DETAILS="${DETAILS}포트 ${port}: LISTEN 상태
    "
            fi
        done

        if [ -n "$RUNNING" ]; then
            RES="N"
            DESC="tftp, talk 서비스가 활성화되어 있음"
        else
            RES="Y"
            DESC="tftp, talk 서비스가 비활성화됨"
            DETAILS="tftp, talk, ntalk: 미실행"
        fi

        DT="$DETAILS"

    output_checkpoint "$CODE" "$CAT" "$NAME" "$IMP" "$STD" "$RES" "$DESC" "$DT"
}

check45() {
    local CODE="U-45"
    local CAT="서비스관리"
    local NAME="메일 서비스 버전 점검"
    local IMP="상"
    local STD="메일 서비스 버전이 최신 버전인 경우"
    local RES=""
    local DESC=""
    local DT=""

        typeset DETAILS=""
        typeset MAIL_FOUND="false"

        # Sendmail 프로세스 및 버전 확인
        if is_process_running "sendmail"; then
            MAIL_FOUND="true"
            typeset SM_VERSION=""
            if [ -x /usr/sbin/sendmail ]; then
                SM_VERSION=$(/usr/sbin/sendmail -d0.1 -bv root 2>&1 | grep "Version" | head -1)
            elif [ -x /usr/lib/sendmail ]; then
                SM_VERSION=$(/usr/lib/sendmail -d0.1 -bv root 2>&1 | grep "Version" | head -1)
            fi
            if [ -n "$SM_VERSION" ]; then
                DETAILS="${DETAILS}Sendmail: ${SM_VERSION}
    "
            else
                DETAILS="${DETAILS}Sendmail: 실행 중 (버전 확인 불가)
    "
            fi
        fi

        # Postfix 프로세스 및 버전 확인
        if is_process_running "postfix"; then
            MAIL_FOUND="true"
            typeset PF_VERSION=""
            PF_VERSION=$(postconf mail_version 2>/dev/null | cut -d'=' -f2 | tr -d ' ')
            DETAILS="${DETAILS}Postfix: ${PF_VERSION:-버전 확인 불가}
    "
        fi

        # Exim 프로세스 및 버전 확인
        if is_process_running "exim"; then
            MAIL_FOUND="true"
            typeset EXIM_VERSION=""
            EXIM_VERSION=$(exim -bV 2>/dev/null | grep "Exim version" | head -1)
            DETAILS="${DETAILS}Exim: ${EXIM_VERSION:-버전 확인 불가}
    "
        fi

        if [ "$MAIL_FOUND" = "true" ]; then
            RES="M"
            DESC="메일 서비스 버전 수동 확인 필요 (최신 패치 여부 확인)"
        else
            RES="N/A"
            DESC="메일 서비스가 실행되지 않음"
            DETAILS="sendmail/postfix/exim: 미실행"
        fi

        DT="$DETAILS"

    output_checkpoint "$CODE" "$CAT" "$NAME" "$IMP" "$STD" "$RES" "$DESC" "$DT"
}

check46() {
    local CODE="U-46"
    local CAT="서비스관리"
    local NAME="일반 사용자의 메일 서비스 실행 방지"
    local IMP="상"
    local STD="일반 사용자의 메일 서비스 실행 방지가 설정된 경우"
    local RES=""
    local DESC=""
    local DT=""

        typeset DETAILS=""
        typeset HAS_ISSUE="false"

        # Sendmail 확인
        if is_process_running "sendmail"; then
            # sendmail.cf의 PrivacyOptions에서 restrictqrun 확인
            typeset SENDMAIL_CF=""
            for cf in /etc/mail/sendmail.cf /etc/sendmail.cf; do
                if [ -f "$cf" ]; then
                    SENDMAIL_CF="$cf"
                    break
                fi
            done

            if [ -n "$SENDMAIL_CF" ]; then
                typeset PRIVACY=""
                PRIVACY=$(grep -i "^O PrivacyOptions" "$SENDMAIL_CF" 2>/dev/null)
                DETAILS="${DETAILS}sendmail.cf: ${SENDMAIL_CF}
    PrivacyOptions: ${PRIVACY:-not set}
    "
                if echo "$PRIVACY" | grep -qi "restrictqrun"; then
                    DETAILS="${DETAILS}  restrictqrun: 설정됨 (양호)
    "
                else
                    HAS_ISSUE="true"
                    DETAILS="${DETAILS}  restrictqrun: 미설정 (취약)
    "
                fi
            else
                HAS_ISSUE="true"
                DETAILS="${DETAILS}sendmail.cf: 파일 없음
    "
            fi

            if [ "$HAS_ISSUE" = "true" ]; then
                RES="N"
                DESC="일반 사용자의 메일 서비스 실행 방지가 설정되어 있지 않음"
            else
                RES="Y"
                DESC="일반 사용자의 메일 서비스 실행 방지가 설정됨"
            fi

        # Postfix 확인
        elif is_process_running "postfix"; then
            typeset POSTSUPER_PERM=""
            if [ -f /usr/sbin/postsuper ]; then
                POSTSUPER_PERM=$(get_file_perm /usr/sbin/postsuper)
                DETAILS="postsuper 권한: ${POSTSUPER_PERM}
    "
                # other에 실행 권한이 있으면 취약
                typeset OTHER_X=""
                OTHER_X=$(expr "$POSTSUPER_PERM" % 10)
                if [ "$OTHER_X" -ge 1 ] 2>/dev/null; then
                    RES="N"
                    DESC="Postfix 큐 관리 도구에 일반 사용자 실행 권한 존재"
                else
                    RES="Y"
                    DESC="Postfix 큐 관리 도구 실행 권한 제한됨"
                fi
            else
                RES="Y"
                DESC="postsuper 명령어 없음"
                DETAILS="postsuper: 미설치"
            fi

        else
            RES="N/A"
            DESC="메일 서비스가 실행되지 않음"
            DETAILS="sendmail/postfix: 미실행"
        fi

        DT="$DETAILS"

    output_checkpoint "$CODE" "$CAT" "$NAME" "$IMP" "$STD" "$RES" "$DESC" "$DT"
}

check47() {
    local CODE="U-47"
    local CAT="서비스관리"
    local NAME="스팸 메일 릴레이 제한"
    local IMP="상"
    local STD="릴레이 제한이 설정된 경우"
    local RES=""
    local DESC=""
    local DT=""

        typeset DETAILS=""

        # Sendmail 프로세스 확인
        if is_process_running "sendmail"; then
            # sendmail.cf 파일 찾기
            typeset SENDMAIL_CF=""
            for cf in /etc/mail/sendmail.cf /etc/sendmail.cf; do
                if [ -f "$cf" ]; then
                    SENDMAIL_CF="$cf"
                    break
                fi
            done

            if [ -z "$SENDMAIL_CF" ]; then
                RES="N"
                DESC="sendmail.cf 파일을 찾을 수 없음"
                DT="sendmail.cf: 없음"
            else
                # promiscuous_relay 확인 (허용 시 취약)
                typeset RELAY_SET=""
                RELAY_SET=$(grep -i "promiscuous_relay" "$SENDMAIL_CF" 2>/dev/null | grep -v "^#")

                # /etc/mail/access 파일 확인
                typeset ACCESS_FILE=""
                if [ -f /etc/mail/access ]; then
                    ACCESS_FILE=$(grep -v "^#" /etc/mail/access 2>/dev/null | grep -v "^$" | head -5)
                fi

                DETAILS="sendmail.cf: ${SENDMAIL_CF}
    릴레이 설정: ${RELAY_SET:-promiscuous_relay 미설정}
    access 파일: ${ACCESS_FILE:-없거나 비어있음}"

                if [ -n "$RELAY_SET" ]; then
                    RES="N"
                    DESC="SMTP 릴레이가 제한되지 않음 (promiscuous_relay 설정)"
                else
                    RES="Y"
                    DESC="SMTP 릴레이가 제한됨"
                fi
            fi

        # Postfix 확인
        elif is_process_running "postfix"; then
            typeset MAIN_CF=""
            for cf in /etc/postfix/main.cf /usr/local/etc/postfix/main.cf; do
                if [ -f "$cf" ]; then
                    MAIN_CF="$cf"
                    break
                fi
            done

            if [ -z "$MAIN_CF" ]; then
                RES="M"
                DESC="Postfix 설정 파일을 찾을 수 없음"
                DT="main.cf: 없음"
            else
                typeset RELAY_CFG=""
                RELAY_CFG=$(grep -E "^(mynetworks|smtpd_recipient_restrictions)" "$MAIN_CF" 2>/dev/null | head -5)
                DETAILS="main.cf: ${MAIN_CF}
    릴레이 설정:
    ${RELAY_CFG:-설정 없음}"
                RES="M"
                DESC="Postfix 릴레이 설정 수동 확인 필요"
            fi

        else
            RES="N/A"
            DESC="메일 서비스가 실행되지 않음"
            DETAILS="sendmail/postfix: 미실행"
        fi

        DT="$DETAILS"

    output_checkpoint "$CODE" "$CAT" "$NAME" "$IMP" "$STD" "$RES" "$DESC" "$DT"
}

check48() {
    local CODE="U-48"
    local CAT="서비스관리"
    local NAME="expn, vrfy 명령어 제한"
    local IMP="중"
    local STD="noexpn, novrfy 옵션이 설정된 경우"
    local RES=""
    local DESC=""
    local DT=""

        typeset DETAILS=""

        # Sendmail 프로세스 확인
        if is_process_running "sendmail"; then
            # sendmail.cf 파일 찾기
            typeset SENDMAIL_CF=""
            for cf in /etc/mail/sendmail.cf /etc/sendmail.cf; do
                if [ -f "$cf" ]; then
                    SENDMAIL_CF="$cf"
                    break
                fi
            done

            if [ -z "$SENDMAIL_CF" ]; then
                RES="N"
                DESC="sendmail.cf 파일을 찾을 수 없음"
                DT="sendmail.cf: 없음"
            else
                # PrivacyOptions에서 noexpn, novrfy 또는 goaway 확인
                typeset PRIVACY_OPT=""
                PRIVACY_OPT=$(grep "^O PrivacyOptions" "$SENDMAIL_CF" 2>/dev/null)

                DETAILS="sendmail.cf: ${SENDMAIL_CF}
    PrivacyOptions: ${PRIVACY_OPT:-not set}"

                if echo "$PRIVACY_OPT" | grep -qi "goaway"; then
                    RES="Y"
                    DESC="expn, vrfy 명령어가 제한됨 (goaway)"
                elif echo "$PRIVACY_OPT" | grep -qi "noexpn"; then
                    if echo "$PRIVACY_OPT" | grep -qi "novrfy"; then
                        RES="Y"
                        DESC="expn, vrfy 명령어가 제한됨"
                    else
                        RES="N"
                        DESC="vrfy 명령어가 제한되지 않음"
                    fi
                else
                    RES="N"
                    DESC="expn, vrfy 명령어가 제한되지 않음"
                fi
            fi

        # Postfix 확인
        elif is_process_running "postfix"; then
            typeset MAIN_CF=""
            for cf in /etc/postfix/main.cf /usr/local/etc/postfix/main.cf; do
                if [ -f "$cf" ]; then
                    MAIN_CF="$cf"
                    break
                fi
            done

            if [ -z "$MAIN_CF" ]; then
                RES="M"
                DESC="Postfix 설정 파일을 찾을 수 없음"
                DT="main.cf: 없음"
            else
                typeset VRFY_CMD=""
                VRFY_CMD=$(grep -i "^disable_vrfy_command" "$MAIN_CF" 2>/dev/null)
                DETAILS="main.cf: ${MAIN_CF}
    disable_vrfy_command: ${VRFY_CMD:-not set}"

                if echo "$VRFY_CMD" | grep -qi "yes"; then
                    RES="Y"
                    DESC="vrfy 명령어가 제한됨"
                else
                    RES="N"
                    DESC="vrfy 명령어가 제한되지 않음"
                fi
            fi

        else
            RES="N/A"
            DESC="메일 서비스가 실행되지 않음"
            DETAILS="sendmail/postfix: 미실행"
        fi

        DT="$DETAILS"

    output_checkpoint "$CODE" "$CAT" "$NAME" "$IMP" "$STD" "$RES" "$DESC" "$DT"
}

check49() {
    local CODE="U-49"
    local CAT="서비스관리"
    local NAME="DNS 보안 버전 패치"
    local IMP="상"
    local STD="주기적으로 패치를 관리하는 경우"
    local RES=""
    local DESC=""
    local DT=""

        typeset DETAILS=""

        # named 프로세스 확인
        if is_process_running "named"; then
            # BIND 버전 확인
            typeset NAMED_VER=""
            if [ -x /usr/sbin/named ]; then
                NAMED_VER=$(/usr/sbin/named -v 2>/dev/null)
            fi
            if [ -z "$NAMED_VER" ]; then
                NAMED_VER=$(named -v 2>/dev/null)
            fi

            if [ -n "$NAMED_VER" ]; then
                DETAILS="BIND 버전: ${NAMED_VER}
    "
            else
                DETAILS="named: 실행 중 (버전 확인 불가)
    "
            fi

            # HP-UX: /etc/rc.config.d/namesrvs의 NAMED 설정 확인
            if [ -f /etc/rc.config.d/namesrvs ]; then
                typeset NAMED_SET=""
                NAMED_SET=$(grep "^NAMED" /etc/rc.config.d/namesrvs 2>/dev/null | head -1)
                DETAILS="${DETAILS}namesrvs: ${NAMED_SET:-not set}
    "
            fi

            RES="M"
            DESC="DNS 서비스 버전 수동 확인 필요 (최신 패치 여부 확인)"
        else
            # named가 미실행이더라도 설정 활성화 여부 확인
            if [ -f /etc/rc.config.d/namesrvs ]; then
                typeset NAMED_SET=""
                NAMED_SET=$(grep "^NAMED=" /etc/rc.config.d/namesrvs 2>/dev/null | cut -d'=' -f2)
                if [ "$NAMED_SET" = "1" ]; then
                    DETAILS="named 프로세스: 미실행, NAMED=1 (설정은 활성)
    "
                    RES="M"
                    DESC="DNS 설정이 활성화되어 있으나 프로세스 미실행"
                else
                    RES="N/A"
                    DESC="DNS 서비스가 실행되지 않음"
                    DETAILS="named: 미실행, NAMED 비활성"
                fi
            else
                RES="N/A"
                DESC="DNS 서비스가 실행되지 않음"
                DETAILS="named: 미실행"
            fi
        fi

        DT="$DETAILS"

    output_checkpoint "$CODE" "$CAT" "$NAME" "$IMP" "$STD" "$RES" "$DESC" "$DT"
}

check50() {
    local CODE="U-50"
    local CAT="서비스관리"
    local NAME="DNS ZoneTransfer 설정"
    local IMP="상"
    local STD="Zone Transfer를 허가된 사용자에게만 허용한 경우"
    local RES=""
    local DESC=""
    local DT=""

        typeset DETAILS=""

        # named 프로세스 확인
        if ! is_process_running "named"; then
            RES="N/A"
            DESC="DNS 서비스가 실행되지 않음"
            DT="named: 미실행"
            return
        fi

        # DNS 설정 파일 찾기
        typeset NAMED_CONF=""
        for conf in /etc/named.conf /etc/bind/named.conf /etc/named.boot /etc/bind/named.boot; do
            if [ -f "$conf" ]; then
                NAMED_CONF="$conf"
                break
            fi
        done

        if [ -z "$NAMED_CONF" ]; then
            RES="M"
            DESC="DNS 설정 파일을 찾을 수 없음"
            DT="named.conf/named.boot: 없음 (수동 확인 필요)"
            return
        fi

        DETAILS="DNS 설정 파일: ${NAMED_CONF}
    "

        # named.conf: allow-transfer 확인
        typeset ALLOW_TRANSFER=""
        ALLOW_TRANSFER=$(grep -i "allow-transfer" "$NAMED_CONF" 2>/dev/null | grep -v "^#" | grep -v "^//")

        # named.boot: xfrnets 확인
        typeset XFRNETS=""
        XFRNETS=$(grep -i "xfrnets" "$NAMED_CONF" 2>/dev/null | grep -v "^#")

        if [ -n "$ALLOW_TRANSFER" ]; then
            DETAILS="${DETAILS}allow-transfer: ${ALLOW_TRANSFER}
    "
            # allow-transfer { none; } 또는 특정 IP만 허용하면 양호
            if echo "$ALLOW_TRANSFER" | grep -qi "none"; then
                RES="Y"
                DESC="Zone Transfer가 차단됨 (none)"
            elif echo "$ALLOW_TRANSFER" | grep -qi "any"; then
                RES="N"
                DESC="Zone Transfer가 모든 호스트에 허용됨 (any)"
            else
                RES="M"
                DESC="Zone Transfer 설정 수동 확인 필요"
            fi
        elif [ -n "$XFRNETS" ]; then
            DETAILS="${DETAILS}xfrnets: ${XFRNETS}
    "
            RES="M"
            DESC="Zone Transfer xfrnets 설정 수동 확인 필요"
        else
            RES="N"
            DESC="Zone Transfer 제한 설정이 없음"
            DETAILS="${DETAILS}allow-transfer/xfrnets: 미설정
    "
        fi

        DT="$DETAILS"

    output_checkpoint "$CODE" "$CAT" "$NAME" "$IMP" "$STD" "$RES" "$DESC" "$DT"
}

check51() {
    local CODE="U-51"
    local CAT="서비스관리"
    local NAME="DNS 서비스의 취약한 동적 업데이트 설정 금지"
    local IMP="중"
    local STD="DNS 서비스의 동적 업데이트 기능이 비활성화되었거나, 활성화 시 적절한 접근통제를 수행하고 있는 경우"
    local RES=""
    local DESC=""
    local DT=""

    typeset NAMED_CONF="/etc/named.conf"

    if [ ! -f "$NAMED_CONF" ]; then
        RES="N/A"
        DESC="DNS 설정 파일이 없음"
        DT="$NAMED_CONF: 없음"
    else
        typeset ALLOW_UPDATE=""
        ALLOW_UPDATE=$(grep -i "allow-update" "$NAMED_CONF" 2>/dev/null)

        if [ -z "$ALLOW_UPDATE" ]; then
            RES="Y"
            DESC="동적 업데이트가 설정되지 않음"
            DT="allow-update: not set"
        elif echo "$ALLOW_UPDATE" | grep -q "none"; then
            RES="Y"
            DESC="동적 업데이트가 제한됨"
            DT="$ALLOW_UPDATE"
        else
            RES="M"
            DESC="동적 업데이트 설정 수동 확인 필요"
            DT="$ALLOW_UPDATE"
        fi
    fi

    output_checkpoint "$CODE" "$CAT" "$NAME" "$IMP" "$STD" "$RES" "$DESC" "$DT"
}

check52() {
    local CODE="U-52"
    local CAT="서비스관리"
    local NAME="Telnet 서비스 비활성화"
    local IMP="중"
    local STD="원격 접속 시 Telnet 프로토콜을 비활성화하고 있는 경우"
    local RES=""
    local DESC=""
    local DT=""

    typeset RUNNING="false"
    typeset DETAILS=""

    # telnetd 프로세스 확인
    if is_process_running "telnetd"; then
        RUNNING="true"
        DETAILS="telnetd 프로세스: 실행 중"
    fi

    # /etc/inetd.conf 에서 telnet 활성화 여부 확인
    if [ -f /etc/inetd.conf ]; then
        typeset TELNET_LINE=""
        TELNET_LINE=$(grep -v "^#" /etc/inetd.conf 2>/dev/null | grep -i "telnet")
        if [ -n "$TELNET_LINE" ]; then
            RUNNING="true"
            DETAILS="${DETAILS} inetd.conf: telnet 활성화"
        fi
    fi

    if [ "$RUNNING" = "true" ]; then
        RES="N"
        DESC="Telnet 서비스가 활성화됨"
    else
        RES="Y"
        DESC="Telnet 서비스가 비활성화됨"
        DETAILS="telnet: 미실행"
    fi

    DT="$DETAILS"

    output_checkpoint "$CODE" "$CAT" "$NAME" "$IMP" "$STD" "$RES" "$DESC" "$DT"
}

check53() {
    local CODE="U-53"
    local CAT="서비스관리"
    local NAME="FTP 서비스 정보 노출 제한"
    local IMP="하"
    local STD="FTP 접속 배너에 노출되는 정보가 없는 경우"
    local RES=""
    local DESC=""
    local DT=""

    typeset DETAILS=""

    # HP-UX ftpaccess 확인 (Wu-ftpd)
    if [ -f /etc/ftpd/ftpaccess ]; then
        typeset GREETING=""
        GREETING=$(grep -i "greeting\|suppresshostname\|suppressversion\|banner" /etc/ftpd/ftpaccess 2>/dev/null)
        DETAILS="ftpaccess: ${GREETING:-설정 없음}"
        RES="M"
        DESC="FTP 배너 설정 수동 확인 필요"
    # vsftpd 확인
    elif [ -f /etc/vsftpd.conf ]; then
        typeset BANNER=""
        BANNER=$(grep -i "ftpd_banner" /etc/vsftpd.conf 2>/dev/null)
        DETAILS="vsftpd 배너: ${BANNER:-기본값}"
        RES="M"
        DESC="FTP 배너 설정 수동 확인 필요"
    # proftpd 확인
    elif [ -f /etc/proftpd.conf ]; then
        typeset BANNER=""
        BANNER=$(grep -i "ServerIdent" /etc/proftpd.conf 2>/dev/null)
        DETAILS="proftpd ServerIdent: ${BANNER:-기본값}"
        RES="M"
        DESC="FTP 배너 설정 수동 확인 필요"
    else
        RES="N/A"
        DESC="FTP 서비스 설정 파일 없음"
        DETAILS="ftpaccess/vsftpd.conf/proftpd.conf: 없음"
    fi

    DT="$DETAILS"

    output_checkpoint "$CODE" "$CAT" "$NAME" "$IMP" "$STD" "$RES" "$DESC" "$DT"
}

check54() {
    local CODE="U-54"
    local CAT="서비스관리"
    local NAME="암호화되지 않는 FTP 서비스 비활성화"
    local IMP="중"
    local STD="암호화되지 않은 FTP 서비스가 비활성화된 경우"
    local RES=""
    local DESC=""
    local DT=""

    typeset RUNNING="false"
    typeset DETAILS=""

    # FTP 프로세스 확인
    if is_process_running "ftpd"; then
        RUNNING="true"
        DETAILS="ftpd 프로세스: 실행 중"
    fi
    if is_process_running "vsftpd"; then
        RUNNING="true"
        DETAILS="${DETAILS} vsftpd 프로세스: 실행 중"
    fi
    if is_process_running "proftpd"; then
        RUNNING="true"
        DETAILS="${DETAILS} proftpd 프로세스: 실행 중"
    fi

    # /etc/inetd.conf 에서 ftp 활성화 여부 확인
    if [ -f /etc/inetd.conf ]; then
        typeset FTP_LINE=""
        FTP_LINE=$(grep -v "^#" /etc/inetd.conf 2>/dev/null | grep -i "^ftp")
        if [ -n "$FTP_LINE" ]; then
            RUNNING="true"
            DETAILS="${DETAILS} inetd.conf: ftp 활성화"
        fi
    fi

    if [ "$RUNNING" = "true" ]; then
        # SSL/TLS 설정 확인
        if [ -f /etc/vsftpd.conf ]; then
            if grep -qi "ssl_enable=YES" /etc/vsftpd.conf 2>/dev/null; then
                RES="Y"
                DESC="FTP SSL/TLS가 활성화됨"
            else
                RES="N"
                DESC="FTP가 암호화 없이 실행 중"
            fi
        else
            RES="N"
            DESC="FTP가 암호화 없이 실행 중"
        fi
    else
        RES="Y"
        DESC="FTP 서비스가 비활성화됨"
        DETAILS="FTP: 미실행"
    fi

    DT="$DETAILS"

    output_checkpoint "$CODE" "$CAT" "$NAME" "$IMP" "$STD" "$RES" "$DESC" "$DT"
}

check55() {
    local CODE="U-55"
    local CAT="서비스관리"
    local NAME="FTP 계정 shell 제한"
    local IMP="중"
    local STD="FTP 계정에 /bin/false(/sbin/nologin) 쉘이 부여된 경우"
    local RES=""
    local DESC=""
    local DT=""

    # ftp 계정 쉘 확인
    typeset FTP_SHELL=""
    FTP_SHELL=$(grep "^ftp:" /etc/passwd 2>/dev/null | cut -d: -f7)

    if [ -z "$FTP_SHELL" ]; then
        RES="N/A"
        DESC="ftp 계정이 존재하지 않음"
        DT="ftp 계정: 없음"
    else
        case "$FTP_SHELL" in
            */nologin|*/false)
                RES="Y"
                DESC="ftp 계정에 쉘이 제한됨"
                ;;
            *)
                RES="N"
                DESC="ftp 계정에 쉘이 부여됨"
                ;;
        esac
        DT="ftp 쉘: $FTP_SHELL"
    fi

    output_checkpoint "$CODE" "$CAT" "$NAME" "$IMP" "$STD" "$RES" "$DESC" "$DT"
}

check56() {
    local CODE="U-56"
    local CAT="서비스관리"
    local NAME="FTP 서비스 접근 제어 설정"
    local IMP="하"
    local STD="특정 IP주소 또는 호스트에서만 FTP 서버에 접속할 수 있도록 접근 제어 설정을 적용한 경우"
    local RES=""
    local DESC=""
    local DT=""

    typeset DETAILS=""
    typeset HAS_CONTROL="false"

    # ftpusers 파일 확인 (HP-UX 경로)
    if [ -f /etc/ftpd/ftpusers ]; then
        HAS_CONTROL="true"
        DETAILS="ftpusers: /etc/ftpd/ftpusers 존재"
    elif [ -f /etc/ftpusers ]; then
        HAS_CONTROL="true"
        DETAILS="ftpusers: /etc/ftpusers 존재"
    fi

    # hosts.allow/deny 확인
    if grep -qi "ftpd" /etc/hosts.allow 2>/dev/null; then
        HAS_CONTROL="true"
        DETAILS="${DETAILS} hosts.allow: FTP 설정 존재"
    fi
    if grep -qi "ftpd" /etc/hosts.deny 2>/dev/null; then
        HAS_CONTROL="true"
        DETAILS="${DETAILS} hosts.deny: FTP 설정 존재"
    fi

    # vsftpd tcp_wrappers 확인
    if [ -f /etc/vsftpd.conf ]; then
        typeset TCP_WRAP=""
        TCP_WRAP=$(grep -i "tcp_wrappers" /etc/vsftpd.conf 2>/dev/null)
        DETAILS="${DETAILS} vsftpd tcp_wrappers: ${TCP_WRAP:-not set}"
    fi

    # ftpaccess 접근 제어 확인 (HP-UX Wu-ftpd)
    if [ -f /etc/ftpd/ftpaccess ]; then
        typeset FTP_ACCESS=""
        FTP_ACCESS=$(grep -i "deny\|allow\|limit" /etc/ftpd/ftpaccess 2>/dev/null)
        if [ -n "$FTP_ACCESS" ]; then
            HAS_CONTROL="true"
            DETAILS="${DETAILS} ftpaccess: 접근 제어 설정 존재"
        fi
    fi

    if [ "$HAS_CONTROL" = "true" ]; then
        RES="Y"
        DESC="FTP 접근 제어가 설정됨"
    else
        RES="M"
        DESC="FTP 접근 제어 수동 확인 필요"
    fi

    DT="$DETAILS"

    output_checkpoint "$CODE" "$CAT" "$NAME" "$IMP" "$STD" "$RES" "$DESC" "$DT"
}

check57() {
    local CODE="U-57"
    local CAT="서비스관리"
    local NAME="Ftpusers 파일 설정"
    local IMP="중"
    local STD="root 계정 접속을 차단한 경우"
    local RES=""
    local DESC=""
    local DT=""

        typeset FTPUSERS=""

        # HP-UX ftpusers 파일 경로 확인
        if [ -f /etc/ftpd/ftpusers ]; then
            FTPUSERS="/etc/ftpd/ftpusers"
        elif [ -f /etc/ftpusers ]; then
            FTPUSERS="/etc/ftpusers"
        elif [ -f /etc/vsftpd/ftpusers ]; then
            FTPUSERS="/etc/vsftpd/ftpusers"
        fi

        if [ -z "$FTPUSERS" ]; then
            RES="N/A"
            DESC="ftpusers 파일이 없음"
            DT="ftpusers: 없음"
        else
            typeset ROOT_DENIED=""
            ROOT_DENIED=$(grep "^root" "$FTPUSERS" 2>/dev/null)
            typeset CONTENT=""
            CONTENT=$(head -10 "$FTPUSERS" 2>/dev/null)

            if [ -n "$ROOT_DENIED" ]; then
                RES="Y"
                DESC="root 계정이 ftpusers에 등록됨"
            else
                RES="N"
                DESC="root 계정이 ftpusers에 미등록"
            fi
            DT="$FTPUSERS:
    $CONTENT"
        fi

    output_checkpoint "$CODE" "$CAT" "$NAME" "$IMP" "$STD" "$RES" "$DESC" "$DT"
}

check58() {
    local CODE="U-58"
    local CAT="서비스관리"
    local NAME="불필요한 SNMP 서비스 구동 점검"
    local IMP="중"
    local STD="SNMP 서비스를 사용하지 않는 경우"
    local RES=""
    local DESC=""
    local DT=""

    typeset RUNNING="false"
    typeset DETAILS=""

    # snmpd 프로세스 확인
    if is_process_running "snmpd"; then
        RUNNING="true"
        DETAILS="snmpd 프로세스: 실행 중"
    fi

    # 포트 161 확인
    if netstat -an 2>/dev/null | grep "\.161 " | grep -q LISTEN; then
        RUNNING="true"
        DETAILS="${DETAILS} 포트 161: 사용 중"
    fi

    if [ "$RUNNING" = "true" ]; then
        RES="M"
        DESC="SNMP 서비스 사용 여부 수동 확인 필요"
    else
        RES="Y"
        DESC="SNMP 서비스가 비활성화됨"
        DETAILS="snmpd: 미실행"
    fi

    DT="$DETAILS"

    output_checkpoint "$CODE" "$CAT" "$NAME" "$IMP" "$STD" "$RES" "$DESC" "$DT"
}

check59() {
    local CODE="U-59"
    local CAT="서비스관리"
    local NAME="안전한 SNMP 버전 사용"
    local IMP="상"
    local STD="SNMP 서비스를 v3 이상으로 사용하는 경우"
    local RES=""
    local DESC=""
    local DT=""

        # HP-UX SNMP 설정 파일 경로
        typeset SNMP_CONF=""
        if [ -f /etc/snmpd.conf ]; then
            SNMP_CONF="/etc/snmpd.conf"
        elif [ -f /etc/snmp/snmpd.conf ]; then
            SNMP_CONF="/etc/snmp/snmpd.conf"
        fi

        if [ -z "$SNMP_CONF" ]; then
            if ! is_process_running "snmpd"; then
                RES="N/A"
                DESC="SNMP 서비스가 사용되지 않음"
                DT="snmpd.conf: 없음, snmpd: 미실행"
            else
                RES="M"
                DESC="SNMP 설정 수동 확인 필요"
                DT="snmpd.conf: 없음"
            fi
        else
            typeset V3_CONFIG=""
            V3_CONFIG=$(grep -iE "^rouser|^rwuser|^createUser" "$SNMP_CONF" 2>/dev/null)
            typeset V1V2_CONFIG=""
            V1V2_CONFIG=$(grep -iE "^rocommunity|^rwcommunity|^get-community-name|^set-community-name" "$SNMP_CONF" 2>/dev/null)

            if [ -n "$V3_CONFIG" ] && [ -z "$V1V2_CONFIG" ]; then
                RES="Y"
                DESC="SNMPv3만 사용 중"
                DT="SNMPv3 설정:
    $V3_CONFIG"
            elif [ -n "$V1V2_CONFIG" ]; then
                RES="N"
                DESC="취약한 SNMP 버전(v1/v2c) 사용 중"
                DT="v1/v2c 설정:
    $V1V2_CONFIG"
            else
                RES="M"
                DESC="SNMP 버전 수동 확인 필요"
                DT="설정 파일: $SNMP_CONF"
            fi
        fi

    output_checkpoint "$CODE" "$CAT" "$NAME" "$IMP" "$STD" "$RES" "$DESC" "$DT"
}

check60() {
    local CODE="U-60"
    local CAT="서비스관리"
    local NAME="SNMP Community String 복잡성 설정"
    local IMP="중"
    local STD="SNMP Community String 기본값인 “public”, “private”이 아닌 영문자, 숫자 포함 10자리 이상 또는 영문자, 숫자, 특수문자 포함 8자리 이상인 경우"
    local RES=""
    local DESC=""
    local DT=""

    # HP-UX SNMP 설정 파일 경로
    typeset SNMP_CONF=""
    if [ -f /etc/snmpd.conf ]; then
        SNMP_CONF="/etc/snmpd.conf"
    elif [ -f /etc/snmp/snmpd.conf ]; then
        SNMP_CONF="/etc/snmp/snmpd.conf"
    fi

    if [ -z "$SNMP_CONF" ]; then
        RES="N/A"
        DESC="SNMP 설정 파일이 없음"
        DT="snmpd.conf: 없음"
    else
        typeset COMMUNITIES=""
        typeset HAS_WEAK="false"

        # HP-UX 고유 형식: get-community-name, set-community-name
        typeset HPUX_COMM=""
        HPUX_COMM=$(grep -iE "^get-community-name|^set-community-name" "$SNMP_CONF" 2>/dev/null | awk -F: '{print $2}' | awk '{print $1}')

        # 표준 형식: rocommunity, rwcommunity
        typeset STD_COMM=""
        STD_COMM=$(grep -iE "^rocommunity|^rwcommunity" "$SNMP_CONF" 2>/dev/null | awk '{print $2}')

        COMMUNITIES="${HPUX_COMM} ${STD_COMM}"

        for comm in $COMMUNITIES; do
            case "$comm" in
                public|private|Public|Private|PUBLIC|PRIVATE)
                    HAS_WEAK="true"
                    ;;
            esac
        done

        typeset TRIMMED=""
        TRIMMED=$(echo "$COMMUNITIES" | awk 'NF{print}')

        if [ -z "$TRIMMED" ]; then
            RES="Y"
            DESC="Community String 미사용 (SNMPv3 사용 가능)"
            DT="Community: 설정 없음"
        elif [ "$HAS_WEAK" = "true" ]; then
            RES="N"
            DESC="취약한 Community String 사용 중"
            DT="Community: $TRIMMED"
        else
            RES="Y"
            DESC="Community String이 복잡하게 설정됨"
            DT="Community: $TRIMMED"
        fi
    fi

    output_checkpoint "$CODE" "$CAT" "$NAME" "$IMP" "$STD" "$RES" "$DESC" "$DT"
}

check61() {
    local CODE="U-61"
    local CAT="서비스관리"
    local NAME="SNMP Access Control 설정"
    local IMP="상"
    local STD="SNMP 서비스에 접근 제어 설정이 되어 있는 경우"
    local RES=""
    local DESC=""
    local DT=""

        # HP-UX SNMP 설정 파일 경로
        typeset SNMP_CONF=""
        if [ -f /etc/snmpd.conf ]; then
            SNMP_CONF="/etc/snmpd.conf"
        elif [ -f /etc/snmp/snmpd.conf ]; then
            SNMP_CONF="/etc/snmp/snmpd.conf"
        fi

        if [ -z "$SNMP_CONF" ]; then
            if ! is_process_running "snmpd"; then
                RES="N/A"
                DESC="SNMP 서비스가 사용되지 않음"
                DT="snmpd.conf: 없음, snmpd: 미실행"
            else
                RES="M"
                DESC="SNMP 설정 수동 확인 필요"
                DT="snmpd.conf: 없음"
            fi
        else
            typeset DETAILS=""

            # HP-UX trap-dest 접근 제어 확인
            typeset TRAP_DEST=""
            TRAP_DEST=$(grep -i "^trap-dest" "$SNMP_CONF" 2>/dev/null | head -5)
            if [ -n "$TRAP_DEST" ]; then
                DETAILS="trap-dest 설정:
    $TRAP_DEST"
            fi

            # 표준 접근 제어 설정 확인
            typeset ACCESS_CONTROL=""
            ACCESS_CONTROL=$(grep -iE "^com2sec|^group|^access|^view|^rocommunity|^rwcommunity" "$SNMP_CONF" 2>/dev/null | head -10)
            if [ -n "$ACCESS_CONTROL" ]; then
                DETAILS="${DETAILS}
    접근 제어 설정:
    $ACCESS_CONTROL"
            fi

            # HP-UX 고유 community 네트워크 제한 확인
            typeset COMM_RESTRICT=""
            COMM_RESTRICT=$(grep -iE "^get-community-name|^set-community-name" "$SNMP_CONF" 2>/dev/null)

            if [ -n "$TRAP_DEST" ] || [ -n "$ACCESS_CONTROL" ]; then
                RES="M"
                DESC="SNMP 접근 제어 수동 확인 필요"
            elif [ -n "$COMM_RESTRICT" ]; then
                RES="M"
                DESC="SNMP Community 설정 수동 확인 필요"
                DETAILS="Community 설정:
    $COMM_RESTRICT"
            else
                RES="N"
                DESC="SNMP 접근 제어 미설정"
                DETAILS="접근 제어 설정: 없음"
            fi

            DT="$DETAILS"
        fi

    output_checkpoint "$CODE" "$CAT" "$NAME" "$IMP" "$STD" "$RES" "$DESC" "$DT"
}

check62() {
    local CODE="U-62"
    local CAT="서비스관리"
    local NAME="로그인 시 경고 메시지 설정"
    local IMP="하"
    local STD="서버 및 Telnet, FTP, SMTP, DNS 서비스에 로그온 시 경고 메시지가 설정된 경우"
    local RES=""
    local DESC=""
    local DT=""

        typeset DETAILS=""
        typeset HAS_BANNER="false"

        # /etc/motd 확인
        if [ -f /etc/motd ] && [ -s /etc/motd ]; then
            HAS_BANNER="true"
            typeset MOTD_CONTENT=""
            MOTD_CONTENT=$(head -3 /etc/motd 2>/dev/null)
            DETAILS="/etc/motd: 설정됨
    $MOTD_CONTENT
    "
        fi

        # /etc/issue 확인
        if [ -f /etc/issue ] && [ -s /etc/issue ]; then
            HAS_BANNER="true"
            typeset ISSUE_CONTENT=""
            ISSUE_CONTENT=$(head -3 /etc/issue 2>/dev/null)
            DETAILS="${DETAILS}/etc/issue: 설정됨
    $ISSUE_CONTENT
    "
        fi

        # SSH Banner 확인 (HP-UX 경로)
        typeset SSHD_CFG=""
        if [ -f /opt/ssh/etc/sshd_config ]; then
            SSHD_CFG="/opt/ssh/etc/sshd_config"
        elif [ -f /etc/ssh/sshd_config ]; then
            SSHD_CFG="/etc/ssh/sshd_config"
        fi

        if [ -n "$SSHD_CFG" ]; then
            typeset SSH_BANNER=""
            SSH_BANNER=$(grep "^Banner" "$SSHD_CFG" 2>/dev/null | awk '{print $2}')
            if [ -n "$SSH_BANNER" ] && [ "$SSH_BANNER" != "none" ]; then
                DETAILS="${DETAILS}SSH Banner: $SSH_BANNER"
                HAS_BANNER="true"
            fi
        fi

        # inetd.conf telnet 배너 확인
        if [ -f /etc/inetd.conf ]; then
            typeset TELNET_BANNER=""
            TELNET_BANNER=$(grep -v "^#" /etc/inetd.conf 2>/dev/null | grep telnet | grep "\-b")
            if [ -n "$TELNET_BANNER" ]; then
                DETAILS="${DETAILS} Telnet 배너: 설정됨"
                HAS_BANNER="true"
            fi
        fi

        if [ "$HAS_BANNER" = "true" ]; then
            RES="Y"
            DESC="로그인 경고 메시지가 설정됨"
        else
            RES="N"
            DESC="로그인 경고 메시지가 미설정"
            DETAILS="/etc/motd: 없거나 비어있음
    /etc/issue: 없거나 비어있음
    SSH Banner: 미설정"
        fi

        DT="$DETAILS"

    output_checkpoint "$CODE" "$CAT" "$NAME" "$IMP" "$STD" "$RES" "$DESC" "$DT"
}

check63() {
    local CODE="U-63"
    local CAT="서비스관리"
    local NAME="sudo 명령어 접근 관리"
    local IMP="중"
    local STD="/etc/sudoers 파일 소유자가 root이고, 파일 권한이 640인 경우"
    local RES=""
    local DESC=""
    local DT=""

        typeset SUDOERS="/etc/sudoers"

        if [ ! -f "$SUDOERS" ]; then
            RES="N/A"
            DESC="sudoers 파일이 없음"
            DT="$SUDOERS: 없음"
        else
            typeset HAS_ISSUE="false"
            typeset DETAILS=""

            # 파일 권한 및 소유자 확인 (HP-UX: get_file_perm/get_file_owner)
            typeset OWNER=""
            OWNER=$(get_file_owner "$SUDOERS" 2>/dev/null)
            typeset PERM=""
            PERM=$(get_file_perm "$SUDOERS" 2>/dev/null)

            if [ "$OWNER" != "root" ]; then
                HAS_ISSUE="true"
                DETAILS="소유자: $OWNER (취약 - root 아님)
    "
            else
                DETAILS="소유자: $OWNER (양호)
    "
            fi

            if [ "$PERM" -gt 640 ] 2>/dev/null; then
                HAS_ISSUE="true"
                DETAILS="${DETAILS}권한: $PERM (취약 - 640 초과)
    "
            else
                DETAILS="${DETAILS}권한: $PERM (양호)
    "
            fi

            # NOPASSWD 또는 ALL 권한 확인
            typeset NOPASSWD=""
            NOPASSWD=$(grep -v "^#" "$SUDOERS" 2>/dev/null | grep "NOPASSWD")
            typeset ALL_ALL=""
            ALL_ALL=$(grep -v "^#" "$SUDOERS" 2>/dev/null | grep "ALL=(ALL)")

            if [ -n "$NOPASSWD" ]; then
                DETAILS="${DETAILS}NOPASSWD 설정: 있음
    "
            else
                DETAILS="${DETAILS}NOPASSWD 설정: 없음
    "
            fi

            if [ -n "$ALL_ALL" ]; then
                DETAILS="${DETAILS}ALL 권한: 있음"
            else
                DETAILS="${DETAILS}ALL 권한: 없음"
            fi

            if [ "$HAS_ISSUE" = "true" ]; then
                RES="N"
                DESC="sudoers 파일 권한/소유자 부적절"
            else
                RES="M"
                DESC="sudo 설정 수동 확인 필요"
            fi
            DT="$DETAILS"
        fi

    output_checkpoint "$CODE" "$CAT" "$NAME" "$IMP" "$STD" "$RES" "$DESC" "$DT"
}

check64() {
    local CODE="U-64"
    local CAT="패치관리"
    local NAME="주기적 보안 패치 및 벤더 권고사항 적용"
    local IMP="상"
    local STD="패치 적용 정책을 수립하여 주기적으로 패치 관리를 하고 있으며, 패치 관련 내용을 확인하고 적용하였을 경우"
    local RES=""
    local DESC=""
    local DT=""

        typeset DETAILS=""

        # OS 버전 확인
        typeset OS_VER=""
        OS_VER=$(uname -r 2>/dev/null)
        DETAILS="OS Version: HP-UX $OS_VER
    "

        # 모델 확인
        typeset MODEL=""
        MODEL=$(model 2>/dev/null)
        if [ -n "$MODEL" ]; then
            DETAILS="${DETAILS}Model: $MODEL
    "
        fi

        # 설치된 패치 리스트 확인 (swlist)
        typeset PATCH_COUNT=""
        PATCH_COUNT=$(swlist -l product 2>/dev/null | wc -l)
        if [ -n "$PATCH_COUNT" ]; then
            DETAILS="${DETAILS}설치된 소프트웨어/패치 수: $PATCH_COUNT
    "
        fi

        # 최근 패치 정보 (상위 5개)
        typeset RECENT_PATCHES=""
        RECENT_PATCHES=$(swlist -l product 2>/dev/null | head -10)
        if [ -n "$RECENT_PATCHES" ]; then
            DETAILS="${DETAILS}최근 패치:
    $RECENT_PATCHES
    "
        fi

        # 패치 적용은 수동 확인 필요
        RES="M"
        DESC="패치 적용 현황 수동 확인 필요"
        DT="$DETAILS
    ※ HPE 지원 사이트에서 최신 패치 확인 필요
    https://support.hpe.com/hpsc/patch/content?action=home"

    output_checkpoint "$CODE" "$CAT" "$NAME" "$IMP" "$STD" "$RES" "$DESC" "$DT"
}

check65() {
    local CODE="U-65"
    local CAT="로그관리"
    local NAME="NTP 및 시각 동기화 설정"
    local IMP="중"
    local STD="NTP 및 시각 동기화 설정이 기준에 따라 적용된 경우"
    local RES=""
    local DESC=""
    local DT=""

        typeset DETAILS=""
        typeset NTP_CONFIGURED="false"

        # xntpd 프로세스 확인 (HP-UX NTP 데몬)
        typeset NTP_PROC=""
        NTP_PROC=$(ps -ef 2>/dev/null | grep -v grep | grep -E "xntpd|ntpd")
        if [ -n "$NTP_PROC" ]; then
            DETAILS="NTP 프로세스: 실행 중
    "
            NTP_CONFIGURED="true"
        else
            DETAILS="NTP 프로세스: 미실행
    "
        fi

        # /etc/ntp.conf 설정 확인
        if [ -f /etc/ntp.conf ]; then
            typeset NTP_SERVERS=""
            NTP_SERVERS=$(grep "^server" /etc/ntp.conf 2>/dev/null | head -5)
            if [ -n "$NTP_SERVERS" ]; then
                DETAILS="${DETAILS}/etc/ntp.conf 설정:
    $NTP_SERVERS
    "
                NTP_CONFIGURED="true"
            else
                DETAILS="${DETAILS}/etc/ntp.conf: server 설정 없음
    "
            fi
        else
            DETAILS="${DETAILS}/etc/ntp.conf: 파일 없음
    "
        fi

        # ntpq로 동기화 상태 확인
        if command -v ntpq >/dev/null 2>&1; then
            typeset NTP_STATUS=""
            NTP_STATUS=$(ntpq -pn 2>/dev/null | head -5)
            if [ -n "$NTP_STATUS" ]; then
                DETAILS="${DETAILS}NTP 동기화 상태:
    $NTP_STATUS
    "
            fi
        fi

        # 판단
        if [ "$NTP_CONFIGURED" = "true" ]; then
            RES="Y"
            DESC="NTP 시각 동기화가 설정됨"
        else
            RES="N"
            DESC="NTP 시각 동기화가 설정되지 않음"
        fi

        DT="$DETAILS"

    output_checkpoint "$CODE" "$CAT" "$NAME" "$IMP" "$STD" "$RES" "$DESC" "$DT"
}

check66() {
    local CODE="U-66"
    local CAT="로그관리"
    local NAME="정책에 따른 시스템 로깅 설정"
    local IMP="중"
    local STD="로그 기록 정책이 보안 정책에 따라 설정되어 수립되어 있으며, 로그를 남기고 있는 경우"
    local RES=""
    local DESC=""
    local DT=""

        typeset DETAILS=""
        typeset SYSLOG_CONFIGURED="false"

        # syslogd 프로세스 확인
        typeset SYSLOG_PROC=""
        SYSLOG_PROC=$(ps -ef 2>/dev/null | grep -v grep | grep syslogd)
        if [ -n "$SYSLOG_PROC" ]; then
            DETAILS="syslogd: 실행 중
    "
        else
            DETAILS="syslogd: 미실행
    "
        fi

        # /etc/syslog.conf 설정 확인
        if [ -f /etc/syslog.conf ]; then
            SYSLOG_CONFIGURED="true"
            typeset SYSLOG_SETTINGS=""
            SYSLOG_SETTINGS=$(grep -v "^#" /etc/syslog.conf 2>/dev/null | grep -v "^$" | head -10)
            if [ -n "$SYSLOG_SETTINGS" ]; then
                DETAILS="${DETAILS}/etc/syslog.conf 설정:
    $SYSLOG_SETTINGS
    "
            else
                DETAILS="${DETAILS}/etc/syslog.conf: 유효한 설정 없음
    "
                SYSLOG_CONFIGURED="false"
            fi
        else
            DETAILS="${DETAILS}/etc/syslog.conf: 파일 없음
    "
        fi

        # HP-UX 기본 로그 디렉터리 확인
        typeset LOG_DIR="/var/adm/syslog"
        if [ -d "$LOG_DIR" ]; then
            typeset LOG_FILES=""
            LOG_FILES=$(ls -la "$LOG_DIR" 2>/dev/null | head -10)
            DETAILS="${DETAILS}${LOG_DIR} 디렉터리:
    $LOG_FILES
    "
        fi

        # 주요 로그 파일 존재 확인
        typeset LOG_CHECK=""
        for logfile in /var/adm/syslog/syslog.log /var/adm/syslog/mail.log /var/adm/syslog/auth.log; do
            if [ -f "$logfile" ]; then
                LOG_CHECK="${LOG_CHECK}${logfile}: 존재
    "
            fi
        done
        if [ -n "$LOG_CHECK" ]; then
            DETAILS="${DETAILS}로그 파일:
    $LOG_CHECK"
        fi

        # 판단
        if [ "$SYSLOG_CONFIGURED" = "true" ]; then
            RES="Y"
            DESC="시스템 로깅이 설정됨"
        else
            RES="N"
            DESC="시스템 로깅이 설정되지 않음"
        fi

        DT="$DETAILS"

    output_checkpoint "$CODE" "$CAT" "$NAME" "$IMP" "$STD" "$RES" "$DESC" "$DT"
}

check67() {
    local CODE="U-67"
    local CAT="로그관리"
    local NAME="로그 디렉터리 소유자 및 권한 설정"
    local IMP="중"
    local STD="디렉터리 내 로그 파일의 소유자가 root이고, 권한이 644 이하인 경우"
    local RES=""
    local DESC=""
    local DT=""

        typeset DETAILS=""
        typeset VULNERABLE=""

        # HP-UX 로그 디렉터리 목록
        typeset LOG_DIRS="/var/adm/syslog /var/adm"

        for dir in $LOG_DIRS; do
            if [ -d "$dir" ]; then
                DETAILS="${DETAILS}${dir} 디렉터리:
    "
                # 디렉터리 자체 권한 확인
                typeset dir_perm=""
                typeset dir_owner=""
                dir_perm=$(get_file_perm "$dir" 2>/dev/null)
                dir_owner=$(get_file_owner "$dir" 2>/dev/null)
                DETAILS="${DETAILS}  디렉터리: ${dir_owner}:${dir_perm}
    "

                # 디렉터리 내 로그 파일 권한 확인
                for logfile in "$dir"/*.log "$dir"/syslog "$dir"/wtmp "$dir"/btmp "$dir"/sulog; do
                    if [ -f "$logfile" ]; then
                        typeset perm=""
                        typeset owner=""
                        perm=$(get_file_perm "$logfile" 2>/dev/null)
                        owner=$(get_file_owner "$logfile" 2>/dev/null)
                        typeset fname=""
                        fname=$(basename "$logfile")
                        DETAILS="${DETAILS}  ${fname}: ${owner}:${perm}
    "
                        # 소유자가 root가 아니거나 권한이 644 초과인 경우
                        if [ "$owner" != "root" ] || [ "$perm" -gt 644 ] 2>/dev/null; then
                            VULNERABLE="${VULNERABLE}${logfile} "
                        fi
                    fi
                done
            fi
        done

        # /var/adm/syslog 디렉터리 특별 확인
        typeset SYSLOG_DIR="/var/adm/syslog"
        if [ -d "$SYSLOG_DIR" ]; then
            for logfile in "$SYSLOG_DIR"/*; do
                if [ -f "$logfile" ]; then
                    typeset perm=""
                    typeset owner=""
                    perm=$(get_file_perm "$logfile" 2>/dev/null)
                    owner=$(get_file_owner "$logfile" 2>/dev/null)
                    if [ "$owner" != "root" ] || [ "$perm" -gt 644 ] 2>/dev/null; then
                        case "$VULNERABLE" in
                            *"$logfile"*) ;;
                            *) VULNERABLE="${VULNERABLE}${logfile} " ;;
                        esac
                    fi
                fi
            done
        fi

        # 판단
        if [ -z "$DETAILS" ]; then
            RES="N/A"
            DESC="로그 디렉터리가 존재하지 않음"
            DT="로그 디렉터리: 없음"
        elif [ -z "$VULNERABLE" ]; then
            RES="Y"
            DESC="로그 파일 소유자 및 권한 양호"
            DT="$DETAILS"
        else
            RES="N"
            DESC="로그 파일 소유자 또는 권한 부적절"
            DT="${DETAILS}취약 파일: $VULNERABLE"
        fi

    output_checkpoint "$CODE" "$CAT" "$NAME" "$IMP" "$STD" "$RES" "$DESC" "$DT"
}


#================================================================
# EXECUTE
#================================================================

printf "\n"
printf "  %s Security Assessment v%s [%s]\n" "$META_PLAT" "$META_VER" "$META_STD"
printf "  ─────────────────────────────────────────────────────────\n"
printf "\n"
printf "  호스트: %s\n" "$SYS_HOST"
printf "  OS: %s\n" "$SYS_OS_NAME"
printf "  커널: %s\n" "$SYS_KN"
printf "  IP: %s\n" "$SYS_IP"
printf "\n"
printf "  [진단 시작]\n"
printf "  ─────────────────────────────────────────────────────────\n"
printf "\n"

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
    check27
    check28
    check29
    check30
    check31
    check32
    check33
    check34
    check35
    check36
    check37
    check38
    check39
    check40
    check41
    check42
    check43
    check44
    check45
    check46
    check47
    check48
    check49
    check50
    check51
    check52
    check53
    check54
    check55
    check56
    check57
    check58
    check59
    check60
    check61
    check62
    check63
    check64
    check65
    check66
    check67

# XML 종료
cat >> "$OUTPUT_FILE" << XMLEOF
    </results>
</seedgen>
XMLEOF

#================================================================
# CLEANUP
#================================================================
printf "\n"
printf "  ─────────────────────────────────────────────────────────\n"
printf "\n"
printf "  점검이 완료되었습니다!\n"
printf "  호스트: %s\n" "$SYS_HOST"
printf "  결과 파일: %s\n" "$OUTPUT_FILE"
printf "\n"
