#!/bin/ksh
#================================================================
# AIX 보안 진단 스크립트
# KISA 주요정보통신기반시설 기술적 취약점 분석·평가 기준
#================================================================
# 버전  : 2603070
# 대상  : AIX 6.1, 7.1, 7.2
# 항목  : U-01 ~ U-67 (67개)
# 제작  : Seedgen
#================================================================
META_STD="KISA"

#================================================================
# INIT
#================================================================
META_VER="1.0"
META_PLAT="AIX"
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
# AIX 보안 진단 스크립트
# KISA 주요정보통신기반시설 기술적 취약점 분석·평가 기준
#================================================================
# 버전  : 2603070
# 대상  : AIX 6.1, 7.1, 7.2
# 항목  : U-01 ~ U-67 (67개)
# 제작  : Seedgen
#================================================================
META_STD="KISA"

#================================================================
# INIT
#================================================================
META_VER="1.0"
META_PLAT="AIX"
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
# AIX 플랫폼 헬퍼
#================================================================

# AIX 서비스 실행 확인 (SRC)
is_service_active() {
    typeset svc="$1"
    lssrc -s "$svc" 2>/dev/null | grep -q "active"
}

# inetd 서비스 활성화 확인
is_inetd_service_enabled() {
    typeset svc="$1"
    grep -v "^#" /etc/inetd.conf 2>/dev/null | grep -q "$svc"
}

# /etc/security/user 값 조회 (AIX 스탠자 형식)
get_security_user_value() {
    typeset user="$1"
    typeset key="$2"
    awk -v user="$user" -v key="$key" '
        /^[a-zA-Z]/ { current=$1; gsub(/:$/,"",current) }
        current==user && $0 ~ key { gsub(/.*= */,""); gsub(/[ \t]*$/,""); print }
    ' /etc/security/user 2>/dev/null
}

# AIX 설정 파일 경로
SSHD_CONFIG="/etc/ssh/sshd_config"
SECURITY_USER="/etc/security/user"
SECURITY_PASSWD="/etc/security/passwd"
SECURITY_LOGIN="/etc/security/login.cfg"
INETD_CONF="/etc/inetd.conf"

#================================================================
# COLLECT — 시스템 정보 수집 (AIX)
#================================================================

META_DATE=$(date +%Y-%m-%dT%H:%M:%S)
SYS_HOST=$(hostname)
SYS_DOM=$(domainname 2>/dev/null || echo "N/A")
SYS_OS_NAME="AIX $(oslevel 2>/dev/null || uname -v)"
SYS_OS_FN="AIX"
SYS_KN=$(oslevel -s 2>/dev/null || uname -v)
SYS_ARCH=$(uname -p)

# AIX IP 주소 수집
SYS_IP=$(ifconfig -a 2>/dev/null | grep "inet " | grep -v "127.0.0.1" | head -1 | awk '{print $2}')
SYS_NET_ALL=$(ifconfig -a 2>/dev/null | awk '/^[a-z]/ {iface=$1} /inet / && !/127.0.0.1/ {print iface": "$2}')

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

        typeset DETAILS=""
        typeset SSH_SECURE="N"
        typeset TELNET_SECURE="N"
        typeset SSH_ACTIVE="false"
        typeset TEL_ACTIVE="false"

        # SSH 서비스 확인
        if is_process_running "sshd"; then
            SSH_ACTIVE="true"
        fi

        # Telnet 서비스 확인
        if is_inetd_service_enabled "telnet"; then
            TEL_ACTIVE="true"
        fi

        # SSH 설정 확인
        if [ "$SSH_ACTIVE" = "true" ]; then
            if [ -f "$SSHD_CONFIG" ]; then
                typeset PERMIT=""
                PERMIT=$(grep -i "^PermitRootLogin" "$SSHD_CONFIG" 2>/dev/null | awk '{print $2}' | head -1)
                typeset PERMIT_LOWER=""
                PERMIT_LOWER=$(echo "$PERMIT" | tr 'A-Z' 'a-z')
                DETAILS="SSH PermitRootLogin: ${PERMIT:-not set}"
                if [ "$PERMIT_LOWER" = "no" ]; then
                    SSH_SECURE="Y"
                fi
            else
                DETAILS="SSH 설정 파일 없음 ($SSHD_CONFIG)"
            fi
        else
            DETAILS="SSH: 서비스 미실행"
        fi

        # Telnet 설정 확인 (AIX: /etc/security/user의 root rlogin 설정)
        if [ "$TEL_ACTIVE" = "true" ]; then
            typeset RLOGIN=""
            RLOGIN=$(get_security_user_value "root" "rlogin")
            if [ -z "$RLOGIN" ]; then
                RLOGIN=$(get_security_user_value "default" "rlogin")
            fi
            typeset RLOGIN_LOWER=""
            RLOGIN_LOWER=$(echo "$RLOGIN" | tr 'A-Z' 'a-z')
            DETAILS="${DETAILS}
    Telnet rlogin (root): ${RLOGIN:-not set (default: true)}"
            if [ "$RLOGIN_LOWER" = "false" ]; then
                TELNET_SECURE="Y"
            fi
        else
            DETAILS="${DETAILS}
    Telnet: 서비스 미실행"
        fi

        # 판단
        if [ "$SSH_ACTIVE" = "false" ] && [ "$TEL_ACTIVE" = "false" ]; then
            RES="N/A"
            DESC="원격터미널 서비스(SSH, Telnet)가 실행되지 않음"
        elif [ "$SSH_ACTIVE" = "true" ] && [ "$SSH_SECURE" != "Y" ]; then
            RES="N"
            DESC="root 원격 접속이 허용되어 있음"
        elif [ "$TEL_ACTIVE" = "true" ] && [ "$TELNET_SECURE" != "Y" ]; then
            RES="N"
            DESC="root 원격 접속이 허용되어 있음"
        else
            RES="Y"
            DESC="root 원격 접속이 제한되어 있음"
        fi

        DT="$DETAILS"

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

        # AIX: /etc/security/user 파일에서 default 스탠자 확인
        typeset MINAGE=""
        typeset MAXAGE=""
        typeset MINLEN=""
        typeset MINALPHA=""
        typeset MINOTHER=""
        typeset MINSPECIAL=""
        typeset HISTSIZE=""
        typeset MINDIFF=""

        if [ -f "$SECURITY_USER" ]; then
            MINAGE=$(get_security_user_value "default" "minage")
            MAXAGE=$(get_security_user_value "default" "maxage")
            MINLEN=$(get_security_user_value "default" "minlen")
            MINALPHA=$(get_security_user_value "default" "minalpha")
            MINOTHER=$(get_security_user_value "default" "minother")
            MINSPECIAL=$(get_security_user_value "default" "minspecialchar")
            HISTSIZE=$(get_security_user_value "default" "histsize")
            MINDIFF=$(get_security_user_value "default" "mindiff")

            DETAILS="minage: ${MINAGE:-not set} (주)
    maxage: ${MAXAGE:-not set} (주)
    minlen: ${MINLEN:-not set}
    minalpha: ${MINALPHA:-not set}
    minother: ${MINOTHER:-not set}
    minspecialchar: ${MINSPECIAL:-not set}
    mindiff: ${MINDIFF:-not set}
    histsize: ${HISTSIZE:-not set}"
        else
            RES="N"
            DESC="/etc/security/user 파일이 존재하지 않음"
            DT="/etc/security/user: 파일 없음"
            return
        fi

        # 판단 (AIX maxage는 주 단위, 13주 = 약 91일)
        typeset IS_OK="true"

        if [ -z "$MAXAGE" ] || [ "$MAXAGE" -eq 0 ] 2>/dev/null; then
            IS_OK="false"
            ISSUES="${ISSUES}maxage 미설정, "
        elif [ "$MAXAGE" -gt 13 ] 2>/dev/null; then
            IS_OK="false"
            ISSUES="${ISSUES}maxage 13주(약 91일) 초과, "
        fi

        if [ -z "$MINLEN" ] 2>/dev/null; then
            IS_OK="false"
            ISSUES="${ISSUES}minlen 미설정, "
        elif [ "$MINLEN" -lt 8 ] 2>/dev/null; then
            IS_OK="false"
            ISSUES="${ISSUES}minlen 8자 미만, "
        fi

        if [ -z "$MINALPHA" ] || [ "$MINALPHA" -lt 1 ] 2>/dev/null; then
            IS_OK="false"
            ISSUES="${ISSUES}minalpha 미설정 또는 부족, "
        fi

        if [ -z "$MINOTHER" ] || [ "$MINOTHER" -lt 1 ] 2>/dev/null; then
            IS_OK="false"
            ISSUES="${ISSUES}minother 미설정 또는 부족, "
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

    # AIX: /etc/security/user의 loginretries 확인
    if [ -f "$SECURITY_USER" ]; then
        DENY_VALUE=$(get_security_user_value "default" "loginretries")
        if [ -n "$DENY_VALUE" ]; then
            DETAILS="loginretries: $DENY_VALUE"
        fi
    fi

    # 판단
    if [ -z "$DENY_VALUE" ] || [ "$DENY_VALUE" -eq 0 ] 2>/dev/null; then
        RES="N"
        DESC="계정 잠금 임계값이 설정되지 않음"
        DT="loginretries: ${DENY_VALUE:-not set}"
    elif [ "$DENY_VALUE" -le 10 ] 2>/dev/null; then
        RES="Y"
        DESC="계정 잠금 임계값이 적절히 설정됨"
        DT="$DETAILS (기준: 10회 이하)"
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

        # /etc/passwd 두 번째 필드 확인
        typeset UNPROTECTED=""
        UNPROTECTED=$(awk -F: '$2 != "!" && $2 != "*" && $2 != "" && $2 != "x" {print $1}' /etc/passwd 2>/dev/null)

        # AIX: /etc/security/passwd 파일 존재 여부 (AIX 내장 shadow)
        typeset SECPASSWD_EXISTS="N"
        if [ -f "$SECURITY_PASSWD" ]; then
            SECPASSWD_EXISTS="Y"
        fi

        typeset DETAILS=""
        if [ -z "$UNPROTECTED" ]; then
            DETAILS="/etc/passwd 두 번째 필드: ! 또는 * (암호화됨)"
        else
            DETAILS="/etc/passwd 두 번째 필드: 평문 존재"
        fi
        if [ "$SECPASSWD_EXISTS" = "Y" ]; then
            DETAILS="${DETAILS}
    /etc/security/passwd: 존재함 (AIX 암호화 저장소)"
        else
            DETAILS="${DETAILS}
    /etc/security/passwd: 없음"
        fi

        # AIX는 기본적으로 /etc/security/passwd에 암호화된 비밀번호 저장
        if [ -z "$UNPROTECTED" ] && [ "$SECPASSWD_EXISTS" = "Y" ]; then
            RES="Y"
            DESC="비밀번호가 암호화되어 저장됨"
        else
            RES="N"
            DESC="비밀번호 파일 보호 미흡"
            if [ -n "$UNPROTECTED" ]; then
                DETAILS="${DETAILS}
    암호화 미적용 계정: $UNPROTECTED"
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

        # su 명령어 권한 확인
        typeset SU_PERM=""
        typeset SU_GROUP=""
        if [ -f /usr/bin/su ]; then
            SU_PERM=$(get_file_perm /usr/bin/su)
            SU_GROUP=$(ls -l /usr/bin/su 2>/dev/null | awk '{print $4}')
            DETAILS="${DETAILS}
    su 권한: ${SU_PERM:-확인불가}
    su 그룹: ${SU_GROUP:-확인불가}"

            # su 명령어가 wheel/system 그룹에 속하고 4750 이하 권한인지 확인
            case "$SU_GROUP" in
                system|wheel)
                    case "$SU_PERM" in
                        4750|4710|4700) IS_RESTRICTED="true" ;;
                    esac
                    ;;
            esac
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

        # AIX 기본 불필요 계정 목록
        typeset UNNECESSARY="lp uucp nuucp guest"
        typeset FOUND=""

        for acct in $UNNECESSARY; do
            if grep -q "^${acct}:" /etc/passwd 2>/dev/null; then
                typeset SHELL=""
                SHELL=$(grep "^${acct}:" /etc/passwd | cut -d: -f7)
                case "$SHELL" in
                    */nologin|*/false) ;;
                    *) FOUND="${FOUND}${acct}(${SHELL}) " ;;
                esac
            fi
        done

        # 로그인 가능한 일반 계정 목록
        typeset LOGIN_ACCOUNTS=""
        LOGIN_ACCOUNTS=$(awk -F: '$3 >= 200 && $7 !~ /nologin/ && $7 !~ /false/ {print $1}' /etc/passwd 2>/dev/null | tr '\n' ' ')

        if [ -n "$FOUND" ]; then
            RES="N"
            DESC="불필요한 기본 계정이 존재함"
            DT="점검 계정: $UNNECESSARY
    활성화된 불필요 계정: ${FOUND% }
    로그인 가능 계정: ${LOGIN_ACCOUNTS:-없음}"
        else
            RES="M"
            DESC="불필요한 계정 수동 확인 필요"
            DT="점검 계정: $UNNECESSARY
    활성화된 불필요 계정: 없음
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

        # AIX: system 그룹 (GID 0) 및 root 그룹 확인
        typeset SYSTEM_MEMBERS=""
        SYSTEM_MEMBERS=$(grep "^system:" /etc/group 2>/dev/null | cut -d: -f4)
        typeset ROOT_MEMBERS=""
        ROOT_MEMBERS=$(grep "^root:" /etc/group 2>/dev/null | cut -d: -f4)

        typeset DETAILS=""
        DETAILS="system 그룹 멤버: ${SYSTEM_MEMBERS:-없음}
    root 그룹 멤버: ${ROOT_MEMBERS:-없음}"

        # GID 0인 계정 확인
        typeset GID0_USERS=""
        GID0_USERS=$(awk -F: '$4 == 0 && $1 != "root" {print $1}' /etc/passwd 2>/dev/null)
        DETAILS="${DETAILS}
    GID=0 계정 (root 제외): ${GID0_USERS:-없음}"

        if [ -z "$SYSTEM_MEMBERS" ] && [ -z "$ROOT_MEMBERS" ] && [ -z "$GID0_USERS" ]; then
            RES="Y"
            DESC="관리자 그룹에 최소한의 계정만 포함됨"
        else
            RES="M"
            DESC="관리자 그룹 멤버 확인 필요"
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

    typeset ORPHAN_GIDS=""
    typeset COUNT=0

    while IFS=: read -r gname _ gid _; do
        typeset HAS_USER="false"
        # Primary GID 확인
        if awk -F: -v gid="$gid" '$4 == gid {exit 0} END {exit 1}' /etc/passwd 2>/dev/null; then
            HAS_USER="true"
        fi
        # 그룹 멤버 확인
        typeset MEMBERS=""
        MEMBERS=$(grep "^${gname}:" /etc/group 2>/dev/null | cut -d: -f4)
        if [ -n "$MEMBERS" ]; then
            HAS_USER="true"
        fi
        if [ "$HAS_USER" = "false" ]; then
            ORPHAN_GIDS="${ORPHAN_GIDS}${gname}(${gid}) "
            COUNT=$((COUNT + 1))
        fi
    done < /etc/group

    if [ $COUNT -eq 0 ]; then
        RES="Y"
        DESC="모든 그룹에 계정이 존재함"
        DT="고아 그룹: 없음"
    else
        RES="N"
        DESC="계정이 존재하지 않는 그룹 발견"
        DT="고아 그룹 (${COUNT}개): ${ORPHAN_GIDS% }"
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

        typeset DUP_UIDS=""
        DUP_UIDS=$(awk -F: '{print $3}' /etc/passwd 2>/dev/null | sort -n | uniq -d)

        if [ -z "$DUP_UIDS" ]; then
            RES="Y"
            DESC="중복된 UID가 존재하지 않음"
            DT="중복 UID: 없음"
        else
            typeset DUP_INFO=""
            for uid in $DUP_UIDS; do
                typeset USERS=""
                USERS=$(awk -F: -v uid="$uid" '$3 == uid {print $1}' /etc/passwd 2>/dev/null | tr '\n' ',' | sed 's/,$//')
                DUP_INFO="${DUP_INFO}UID ${uid}: ${USERS}
    "
            done
            RES="N"
            DESC="중복된 UID가 존재함"
            DT="$DUP_INFO"
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

    # 로그인 불필요 시스템 계정 확인
    typeset SYSTEM_ACCTS="daemon bin sys adm uucp lp nuucp guest nobody noaccess diag operator games gopher"
    typeset INVALID_SHELL=""

    for acct in $SYSTEM_ACCTS; do
        if grep -q "^${acct}:" /etc/passwd 2>/dev/null; then
            typeset SHELL=""
            SHELL=$(grep "^${acct}:" /etc/passwd | cut -d: -f7)
            case "$SHELL" in
                */nologin|*/false|"") ;;
                *) INVALID_SHELL="${INVALID_SHELL}${acct}(${SHELL}) " ;;
            esac
        fi
    done

    if [ -z "$INVALID_SHELL" ]; then
        RES="Y"
        DESC="로그인 불필요 계정에 적절한 shell이 설정됨"
        DT="부적절한 shell 계정: 없음"
    else
        RES="N"
        DESC="로그인 가능한 시스템 계정 존재"
        DT="부적절한 shell 계정: ${INVALID_SHELL% }"
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

    # /etc/profile, /etc/environment 확인
    typeset PROFILE_FILES="/etc/profile /etc/environment"
    for profile_file in $PROFILE_FILES; do
        if [ -f "$profile_file" ] && [ -z "$TMOUT_VALUE" ]; then
            typeset FOUND=""
            FOUND=$(grep -E "^[[:space:]]*(export[[:space:]]+)?TMOUT=" "$profile_file" 2>/dev/null | head -1)
            if [ -n "$FOUND" ]; then
                TMOUT_VALUE=$(echo "$FOUND" | sed 's/.*TMOUT=//' | tr -d ' ')
                DETAILS="${profile_file}: TMOUT=${TMOUT_VALUE}"
            fi
        fi
    done

    # root의 .profile 확인
    if [ -z "$TMOUT_VALUE" ] && [ -f /.profile ]; then
        typeset FOUND=""
        FOUND=$(grep -E "^[[:space:]]*(export[[:space:]]+)?TMOUT=" /.profile 2>/dev/null | head -1)
        if [ -n "$FOUND" ]; then
            TMOUT_VALUE=$(echo "$FOUND" | sed 's/.*TMOUT=//' | tr -d ' ')
            DETAILS="/.profile: TMOUT=${TMOUT_VALUE}"
        fi
    fi

    # 판단
    if [ -z "$TMOUT_VALUE" ]; then
        RES="N"
        DESC="세션 종료 시간이 설정되지 않음"
        DT="TMOUT: not set"
    elif [ "$TMOUT_VALUE" -le 600 ] 2>/dev/null; then
        RES="Y"
        DESC="세션 종료 시간이 적절히 설정됨"
        DT="${DETAILS} (기준: 600초 이하)"
    else
        RES="N"
        DESC="세션 종료 시간이 600초 초과"
        DT="${DETAILS} (기준: 600초 이하)"
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
        typeset ALGORITHM=""

        # AIX: /etc/security/login.cfg의 pwd_algorithm 확인
        if [ -f "$SECURITY_LOGIN" ]; then
            ALGORITHM=$(grep "pwd_algorithm" "$SECURITY_LOGIN" 2>/dev/null | grep -v "^[[:space:]]*\*" | grep -v "^#" | head -1 | sed 's/.*=[[:space:]]*//' | tr -d ' \t')
        fi

        # /etc/security/user default 스탠자에서도 확인
        if [ -z "$ALGORITHM" ] && [ -f "$SECURITY_USER" ]; then
            ALGORITHM=$(get_security_user_value "default" "pwd_algorithm")
        fi

        DETAILS="pwd_algorithm: ${ALGORITHM:-not set (기본값 crypt)}"

        # /etc/security/passwd에서 실제 해시 형식 확인
        typeset HASH_SAMPLE=""
        if [ -f "$SECURITY_PASSWD" ]; then
            HASH_SAMPLE=$(grep "password = " "$SECURITY_PASSWD" 2>/dev/null | head -3 | sed 's/.*password = //')
            DETAILS="${DETAILS}
    암호화 해시 샘플: ${HASH_SAMPLE:-확인불가}"
        fi

        # 판단 (ssha256, ssha512 등이 안전, smd5는 취약)
        typeset ALG_LOWER=""
        ALG_LOWER=$(echo "$ALGORITHM" | tr 'A-Z' 'a-z')
        case "$ALG_LOWER" in
            ssha256|ssha512|ssha*)
                RES="Y"
                DESC="안전한 암호화 알고리즘 사용 중"
                ;;
            sblowfish*)
                RES="Y"
                DESC="안전한 암호화 알고리즘 사용 중"
                ;;
            ""|crypt)
                RES="N"
                DESC="기본 crypt 알고리즘 사용 (취약)"
                ;;
            smd5)
                RES="N"
                DESC="MD5 기반 알고리즘 사용 (취약)"
                ;;
            *)
                RES="M"
                DESC="암호화 알고리즘 수동 확인 필요"
                ;;
        esac

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

        typeset ROOT_PATH=""
        ROOT_PATH=$(su - root -c 'echo $PATH' 2>/dev/null)
        typeset HAS_DOT="false"

        # PATH에 . 이 맨앞이나 중간에 있는지 확인
        # .:xxx 또는 xxx:.:xxx 또는 빈 항목(::) 확인
        case "$ROOT_PATH" in
            .:*|*:.:*|*::*) HAS_DOT="true" ;;
        esac

        typeset ROOT_HOME=""
        ROOT_HOME=$(grep "^root:" /etc/passwd | cut -d: -f6)
        typeset ROOT_HOME_PERM=""
        if [ -d "$ROOT_HOME" ]; then
            ROOT_HOME_PERM=$(get_file_perm "$ROOT_HOME")
        fi

        if [ "$HAS_DOT" = "true" ]; then
            RES="N"
            DESC="PATH에 . 이 포함되어 있음"
            DT="PATH: $ROOT_PATH
    root 홈 디렉터리: $ROOT_HOME
    root 홈 권한: ${ROOT_HOME_PERM:-확인불가}"
        elif [ -n "$ROOT_HOME_PERM" ] && [ "$ROOT_HOME_PERM" -gt 750 ] 2>/dev/null; then
            RES="N"
            DESC="root 홈 디렉터리 권한이 과도함"
            DT="root 홈 디렉터리: $ROOT_HOME
    root 홈 권한: $ROOT_HOME_PERM (기준: 750 이하)"
        else
            RES="Y"
            DESC="PATH 및 root 홈 디렉터리 설정 양호"
            DT="PATH: ${ROOT_PATH:-확인불가}
    root 홈 디렉터리: $ROOT_HOME
    root 홈 권한: ${ROOT_HOME_PERM:-확인불가}"
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

        typeset NOOWNER=""
        NOOWNER=$(find /etc /var /tmp -xdev \( -nouser -o -nogroup \) 2>/dev/null | head -20)

        if [ -z "$NOOWNER" ]; then
            RES="Y"
            DESC="소유자가 없는 파일이 존재하지 않음"
            DT="소유자 없는 파일: 없음
    점검 디렉터리: /etc /var /tmp"
        else
            typeset COUNT=""
            COUNT=$(find /etc /var /tmp -xdev \( -nouser -o -nogroup \) 2>/dev/null | wc -l | tr -d ' ')
            RES="N"
            DESC="소유자가 없는 파일이 존재함"
            DT="소유자 없는 파일 (${COUNT}개, 최대 20개 표시):
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
        typeset CHECKED_LIST=""
        # AIX 시스템 시작 스크립트 경로
        typeset TARGETS="/etc/rc.d /etc/rc.d/init.d /etc/rc.d/rc2.d /etc/inittab"

        for target in $TARGETS; do
            if [ -e "$target" ]; then
                typeset PERM=""
                typeset OWNER=""
                PERM=$(get_file_perm "$target")
                OWNER=$(get_file_owner "$target")
                CHECKED_LIST="${CHECKED_LIST}  - ${target} (${OWNER}:${PERM})
    "
                typeset OTHER_PERM=""
                OTHER_PERM=$((PERM % 10))
                if [ "$OWNER" != "root" ] || [ $((OTHER_PERM & 2)) -ne 0 ] 2>/dev/null; then
                    VULNERABLE="${VULNERABLE}${target}(${OWNER}:${PERM}) "
                fi
            fi
        done

        # /etc/rc.d 하위 스크립트 파일도 점검
        if [ -d /etc/rc.d ]; then
            typeset RC_SCRIPTS=""
            RC_SCRIPTS=$(find /etc/rc.d -type f 2>/dev/null | head -30)
            for script in $RC_SCRIPTS; do
                typeset PERM=""
                typeset OWNER=""
                PERM=$(get_file_perm "$script")
                OWNER=$(get_file_owner "$script")
                typeset OTHER_PERM=""
                OTHER_PERM=$((PERM % 10))
                if [ "$OWNER" != "root" ] || [ $((OTHER_PERM & 2)) -ne 0 ] 2>/dev/null; then
                    VULNERABLE="${VULNERABLE}${script}(${OWNER}:${PERM}) "
                fi
            done
        fi

        if [ -z "$CHECKED_LIST" ]; then
            RES="N/A"
            DESC="시스템 시작 스크립트가 존재하지 않음"
            DT="점검 대상: $TARGETS
    검사 결과: 파일 없음"
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
    ${VULNERABLE% }"
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

        typeset TARGET="/etc/security/passwd"

        if [ ! -f "$TARGET" ]; then
            RES="N/A"
            DESC="비밀번호 파일이 존재하지 않음"
            DT="파일: $TARGET (없음)"
        else
            typeset PERM=""
            typeset OWNER=""
            PERM=$(get_file_perm "$TARGET" 2>/dev/null)
            OWNER=$(get_file_owner "$TARGET" 2>/dev/null)

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
            PERM=$(get_file_perm "$TARGET" 2>/dev/null)
            OWNER=$(get_file_owner "$TARGET" 2>/dev/null)

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

        typeset TARGET="/etc/inetd.conf"

        if [ ! -f "$TARGET" ]; then
            RES="N/A"
            DESC="inetd 설정 파일이 존재하지 않음"
            DT="파일: $TARGET (없음)"
        else
            typeset PERM=""
            typeset OWNER=""
            PERM=$(get_file_perm "$TARGET" 2>/dev/null)
            OWNER=$(get_file_owner "$TARGET" 2>/dev/null)

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

check21() {
    local CODE="U-21"
    local CAT="파일및디렉토리관리"
    local NAME="/etc/(r)syslog.conf 파일 소유자 및 권한 설정"
    local IMP="상"
    local STD="/etc/(r)syslog.conf 파일의 소유자가 root(또는 bin, sys)이고, 권한이 640 이하인 경우"
    local RES=""
    local DESC=""
    local DT=""

        typeset TARGET="/etc/syslog.conf"

        if [ ! -f "$TARGET" ]; then
            RES="N/A"
            DESC="syslog 설정 파일이 존재하지 않음"
            DT="파일: $TARGET (없음)"
        else
            typeset PERM=""
            typeset OWNER=""
            PERM=$(get_file_perm "$TARGET" 2>/dev/null)
            OWNER=$(get_file_owner "$TARGET" 2>/dev/null)

            typeset owner_ok="false"
            case "$OWNER" in
                root|bin|sys) owner_ok="true" ;;
            esac

            if [ "$owner_ok" = "true" ] && [ "$PERM" -le 640 ] 2>/dev/null; then
                RES="Y"
                DESC="파일 권한이 적절히 설정됨"
            else
                RES="N"
                DESC="파일 권한이 부적절함"
            fi
            DT="파일: $TARGET
    소유자: $OWNER (기준: root, bin, sys)
    권한: $PERM (기준: 640 이하)"
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
            PERM=$(get_file_perm "$TARGET" 2>/dev/null)
            OWNER=$(get_file_owner "$TARGET" 2>/dev/null)

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
    소유자: $OWNER (기준: root, bin, sys)
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

        typeset SUID_FILES=""
        SUID_FILES=$(find /usr /sbin /bin -xdev -type f \( -perm -4000 -o -perm -2000 \) 2>/dev/null | head -20)

        typeset COUNT=0
        if [ -n "$SUID_FILES" ]; then
            COUNT=$(echo "$SUID_FILES" | wc -l | tr -d ' ')
        fi

        RES="M"
        DESC="SUID/SGID 설정 파일 수동 점검 필요 (${COUNT}개 발견)"
        DT="[SUID/SGID 설정 파일 목록] (상위 20개)
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

        typeset VULNERABLE=""
        typeset DETAILS=""
        typeset ENV_FILES=".profile .kshrc .cshrc .bashrc .bash_profile .login .exrc .netrc"

        # 시스템 환경변수 파일 점검
        typeset SYS_TARGETS="/etc/profile /etc/environment"
        for target in $SYS_TARGETS; do
            if [ -f "$target" ]; then
                typeset perm=""
                typeset owner=""
                perm=$(get_file_perm "$target" 2>/dev/null)
                owner=$(get_file_owner "$target" 2>/dev/null)
                DETAILS="${DETAILS}${target}: ${owner}:${perm}
    "
                typeset other_perm=$((perm % 10))
                if [ "$owner" != "root" ] || [ $((other_perm & 2)) -ne 0 ] 2>/dev/null; then
                    VULNERABLE="${VULNERABLE}${target} "
                fi
            fi
        done

        # 사용자별 홈 디렉토리 환경변수 파일 점검
        while IFS=: read -r user _ uid _ _ home _; do
            if [ "$uid" -ge 100 ] 2>/dev/null && [ -d "$home" ] && [ "$home" != "/" ]; then
                for dotfile in $ENV_FILES; do
                    typeset fpath="${home}/${dotfile}"
                    if [ -f "$fpath" ]; then
                        typeset perm=""
                        typeset owner=""
                        perm=$(get_file_perm "$fpath" 2>/dev/null)
                        owner=$(get_file_owner "$fpath" 2>/dev/null)
                        DETAILS="${DETAILS}${fpath}: ${owner}:${perm}
    "
                        typeset other_perm=$((perm % 10))
                        if [ "$owner" != "$user" ] && [ "$owner" != "root" ]; then
                            VULNERABLE="${VULNERABLE}${fpath}(owner=${owner}) "
                        elif [ $((other_perm & 2)) -ne 0 ] 2>/dev/null; then
                            VULNERABLE="${VULNERABLE}${fpath}(perm=${perm}) "
                        fi
                    fi
                done
            fi
        done < /etc/passwd

        if [ -z "$DETAILS" ]; then
            RES="N/A"
            DESC="점검 대상 환경변수 파일 없음"
            DT="환경변수 파일: 없음"
        elif [ -z "$VULNERABLE" ]; then
            RES="Y"
            DESC="환경변수 파일 소유자 및 권한 양호"
            DT="$DETAILS"
        else
            RES="N"
            DESC="환경변수 파일 소유자 또는 권한 부적절"
            DT="${DETAILS}
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

        typeset SEARCH_DIRS="/etc /var /tmp"
        typeset WW_FILES=""
        WW_FILES=$(find /etc /var /tmp -xdev -type f -perm -0002 ! -type l 2>/dev/null | head -20)

        if [ -z "$WW_FILES" ]; then
            RES="Y"
            DESC="world writable 파일이 존재하지 않음"
            DT="검사 대상: $SEARCH_DIRS
    world writable 파일: 없음"
        else
            typeset COUNT=""
            COUNT=$(echo "$WW_FILES" | wc -l | tr -d ' ')
            RES="N"
            DESC="world writable 파일 ${COUNT}개 발견"
            DT="검사 대상: $SEARCH_DIRS
    world writable 파일 (상위 20개):
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

        typeset DEV_FILES=""
        DEV_FILES=$(find /dev -xdev -type f ! -name ".log" 2>/dev/null | head -20)

        typeset NON_DEV_FILES=""
        NON_DEV_FILES=$(find / -xdev \( -type b -o -type c \) ! -path "/dev/*" 2>/dev/null | head -20)

        typeset ALL_FOUND=""
        if [ -n "$DEV_FILES" ]; then
            ALL_FOUND="${ALL_FOUND}${DEV_FILES}
    "
        fi
        if [ -n "$NON_DEV_FILES" ]; then
            ALL_FOUND="${ALL_FOUND}${NON_DEV_FILES}"
        fi

        if [ -z "$DEV_FILES" ] && [ -z "$NON_DEV_FILES" ]; then
            RES="Y"
            DESC="비정상 device 파일이 존재하지 않음"
            DT="[/dev 내 일반파일]
    없음

    [/dev 외 device 파일]
    없음"
        else
            RES="N"
            DESC="비정상 device 파일이 존재함"
            DT="[/dev 내 일반파일]
    ${DEV_FILES:-없음}

    [/dev 외 device 파일]
    ${NON_DEV_FILES:-없음}"
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

        # r-command 서비스 사용 여부 확인
        typeset R_SVC_RUNNING="false"
        if is_inetd_service_enabled "rlogin" 2>/dev/null || \
           is_inetd_service_enabled "rsh" 2>/dev/null || \
           is_inetd_service_enabled "rexec" 2>/dev/null; then
            R_SVC_RUNNING="true"
        fi

        # /etc/hosts.equiv 점검
        if [ -f /etc/hosts.equiv ]; then
            typeset hperm=""
            typeset howner=""
            hperm=$(get_file_perm /etc/hosts.equiv 2>/dev/null)
            howner=$(get_file_owner /etc/hosts.equiv 2>/dev/null)
            DETAILS="${DETAILS}/etc/hosts.equiv: owner=${howner}, perm=${hperm}
    "
            typeset HAS_PLUS=""
            HAS_PLUS=$(grep "^+" /etc/hosts.equiv 2>/dev/null)
            if [ -n "$HAS_PLUS" ]; then
                VULNERABLE="${VULNERABLE}/etc/hosts.equiv(+ 설정 존재) "
            fi
            if [ "$howner" != "root" ]; then
                VULNERABLE="${VULNERABLE}/etc/hosts.equiv(owner=${howner}) "
            fi
            if [ "$hperm" -gt 600 ] 2>/dev/null; then
                VULNERABLE="${VULNERABLE}/etc/hosts.equiv(perm=${hperm}) "
            fi
        else
            DETAILS="${DETAILS}/etc/hosts.equiv: 없음
    "
        fi

        # 사용자별 $HOME/.rhosts 점검
        while IFS=: read -r user _ uid _ _ home _; do
            if [ -n "$home" ] && [ -d "$home" ]; then
                typeset rhosts="${home}/.rhosts"
                if [ -f "$rhosts" ]; then
                    typeset rperm=""
                    typeset rowner=""
                    rperm=$(get_file_perm "$rhosts" 2>/dev/null)
                    rowner=$(get_file_owner "$rhosts" 2>/dev/null)
                    DETAILS="${DETAILS}${rhosts}: owner=${rowner}, perm=${rperm}
    "
                    typeset RHAS_PLUS=""
                    RHAS_PLUS=$(grep "^+" "$rhosts" 2>/dev/null)
                    if [ -n "$RHAS_PLUS" ]; then
                        VULNERABLE="${VULNERABLE}${rhosts}(+ 설정 존재) "
                    fi
                    if [ "$rowner" != "root" ] && [ "$rowner" != "$user" ]; then
                        VULNERABLE="${VULNERABLE}${rhosts}(owner=${rowner}) "
                    fi
                    if [ "$rperm" -gt 600 ] 2>/dev/null; then
                        VULNERABLE="${VULNERABLE}${rhosts}(perm=${rperm}) "
                    fi
                fi
            fi
        done < /etc/passwd

        if [ "$R_SVC_RUNNING" = "false" ] && [ -z "$VULNERABLE" ]; then
            RES="Y"
            DESC="r-command 서비스 미사용 또는 파일 설정 양호"
        elif [ -n "$VULNERABLE" ]; then
            RES="N"
            DESC="hosts.equiv 또는 .rhosts 파일 설정 취약"
        else
            RES="Y"
            DESC="hosts.equiv 및 .rhosts 파일 설정 양호"
        fi

        DT="[r-command 서비스]
    사용 여부: $R_SVC_RUNNING

    [파일 점검 결과]
    ${DETAILS}
    [취약 항목]
    ${VULNERABLE:-없음}"

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
        typeset HAS_RESTRICT="false"

        # TCP Wrapper: hosts.allow / hosts.deny 확인
        if [ -f /etc/hosts.allow ]; then
            typeset ALLOW_CONTENT=""
            ALLOW_CONTENT=$(grep -v "^#" /etc/hosts.allow 2>/dev/null | grep -v "^$" | head -5)
            if [ -n "$ALLOW_CONTENT" ]; then
                HAS_RESTRICT="true"
                DETAILS="[hosts.allow]
    $ALLOW_CONTENT
    "
            fi
        fi

        if [ -f /etc/hosts.deny ]; then
            typeset DENY_CONTENT=""
            DENY_CONTENT=$(grep -v "^#" /etc/hosts.deny 2>/dev/null | grep -v "^$" | head -5)
            if [ -n "$DENY_CONTENT" ]; then
                HAS_RESTRICT="true"
                DETAILS="${DETAILS}[hosts.deny]
    $DENY_CONTENT
    "
            fi
        fi

        # IPfilter 확인
        if [ -f /etc/ipf/ipf.conf ]; then
            typeset IPF_CONTENT=""
            IPF_CONTENT=$(grep -v "^#" /etc/ipf/ipf.conf 2>/dev/null | grep -v "^$" | head -5)
            if [ -n "$IPF_CONTENT" ]; then
                HAS_RESTRICT="true"
                DETAILS="${DETAILS}[IPfilter /etc/ipf/ipf.conf]
    $IPF_CONTENT
    "
            fi
        fi

        if [ "$HAS_RESTRICT" = "true" ]; then
            RES="Y"
            DESC="접속 IP/포트 제한 설정이 적용됨"
        else
            RES="N"
            DESC="접속 IP/포트 제한이 설정되지 않음"
            DETAILS="hosts.allow/deny: 미설정
    IPfilter: 미설정"
        fi

        DT="$DETAILS"

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
            DESC="hosts.lpd 파일이 존재하지 않음"
            DT="파일: $TARGET (없음)"
        else
            typeset PERM=""
            typeset OWNER=""
            PERM=$(get_file_perm "$TARGET" 2>/dev/null)
            OWNER=$(get_file_owner "$TARGET" 2>/dev/null)

            if [ "$OWNER" = "root" ] && [ "$PERM" -le 600 ] 2>/dev/null; then
                RES="Y"
                DESC="파일 권한이 적절히 설정됨"
            else
                RES="N"
                DESC="파일 권한이 부적절함"
            fi
            DT="파일: $TARGET
    소유자: $OWNER
    권한: $PERM (기준: root 소유, 600 이하)"
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

        typeset DETAILS=""
        typeset UMASK_VALUE=""
        typeset FOUND_PROFILE="false"

        # /etc/profile 파일 내 UMASK 확인
        if [ -f /etc/profile ]; then
            typeset PROFILE_UMASK=""
            PROFILE_UMASK=$(grep -i "^[[:space:]]*umask" /etc/profile 2>/dev/null | awk '{print $2}' | head -1)
            if [ -n "$PROFILE_UMASK" ]; then
                FOUND_PROFILE="true"
                UMASK_VALUE="$PROFILE_UMASK"
                DETAILS="/etc/profile UMASK=${PROFILE_UMASK}
    "
            fi
        fi

        # /etc/security/user 파일 내 default umask 확인 (AIX 전용)
        if [ -f "$SECURITY_USER" ]; then
            typeset SEC_UMASK=""
            SEC_UMASK=$(get_security_user_value "default" "umask" 2>/dev/null)
            if [ -n "$SEC_UMASK" ]; then
                FOUND_PROFILE="true"
                if [ -z "$UMASK_VALUE" ]; then
                    UMASK_VALUE="$SEC_UMASK"
                fi
                DETAILS="${DETAILS}/etc/security/user default umask=${SEC_UMASK}
    "
            fi
        fi

        # 현재 umask 값 확인
        typeset CURRENT_UMASK=""
        CURRENT_UMASK=$(umask)
        DETAILS="${DETAILS}현재 UMASK: $CURRENT_UMASK"

        # 판단: 022 이상(other에 쓰기 권한 미부여)
        typeset IS_OK="false"
        if [ -n "$UMASK_VALUE" ]; then
            if [ "$UMASK_VALUE" -ge 22 ] 2>/dev/null; then
                IS_OK="true"
            fi
        else
            # 파일 설정 없으면 현재 umask로 판단
            typeset CUR_NUM=""
            CUR_NUM=$(echo "$CURRENT_UMASK" | sed 's/^0*//')
            if [ -n "$CUR_NUM" ] && [ "$CUR_NUM" -ge 22 ] 2>/dev/null; then
                IS_OK="true"
            fi
        fi

        if [ "$IS_OK" = "true" ]; then
            RES="Y"
            DESC="UMASK가 022 이상으로 적절히 설정됨"
        else
            RES="N"
            DESC="UMASK가 022 미만으로 설정됨"
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

        while IFS=: read -r user _ uid _ _ home _; do
            if [ "$uid" -ge 100 ] 2>/dev/null && [ -d "$home" ] && [ "$home" != "/" ]; then
                typeset perm=""
                typeset owner=""
                perm=$(get_file_perm "$home" 2>/dev/null)
                owner=$(get_file_owner "$home" 2>/dev/null)
                DETAILS="${DETAILS}${user}: ${home} (owner=${owner}, perm=${perm})
    "
                typeset other_perm=$((perm % 10))
                if [ "$owner" != "$user" ]; then
                    VULNERABLE="${VULNERABLE}${user}:${home}(owner=${owner}) "
                elif [ $((other_perm & 2)) -ne 0 ] 2>/dev/null; then
                    VULNERABLE="${VULNERABLE}${user}:${home}(perm=${perm}) "
                fi
            fi
        done < /etc/passwd

        if [ -z "$DETAILS" ]; then
            RES="N/A"
            DESC="점검 대상 홈 디렉토리 없음"
            DT="홈 디렉토리: 없음"
        elif [ -z "$VULNERABLE" ]; then
            RES="Y"
            DESC="홈 디렉토리 소유자 및 권한 양호"
            DT="$DETAILS
    [취약 항목]
    없음"
        else
            RES="N"
            DESC="홈 디렉토리 소유자 또는 권한 부적절"
            DT="$DETAILS
    [취약 항목]
    $VULNERABLE"
        fi

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

        while IFS=: read -r user _ uid _ _ home _; do
            if [ "$uid" -ge 100 ] 2>/dev/null && [ -n "$home" ] && [ "$home" != "/" ]; then
                if [ ! -d "$home" ]; then
                    MISSING="${MISSING}${user}:${home}
    "
                fi
            fi
        done < /etc/passwd

        if [ -z "$MISSING" ]; then
            RES="Y"
            DESC="모든 홈디렉토리가 존재함"
            DT="누락된 홈디렉토리: 없음"
        else
            RES="N"
            DESC="존재하지 않는 홈디렉토리가 있음"
            DT="[누락된 홈디렉토리]
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

        typeset HIDDEN_FILES=""
        HIDDEN_FILES=$(find /tmp /var/tmp -name ".. *" -o -name ".*" -type f 2>/dev/null | head -20)

        typeset HIDDEN_DIRS=""
        HIDDEN_DIRS=$(find /tmp /var/tmp -name ".*" -type d ! -name "." ! -name ".." 2>/dev/null | head -20)

        typeset ALL_HIDDEN=""
        if [ -n "$HIDDEN_FILES" ]; then
            ALL_HIDDEN="${HIDDEN_FILES}
    "
        fi
        if [ -n "$HIDDEN_DIRS" ]; then
            ALL_HIDDEN="${ALL_HIDDEN}${HIDDEN_DIRS}"
        fi

        if [ -z "$ALL_HIDDEN" ]; then
            RES="Y"
            DESC="비정상 숨김 파일이 발견되지 않음"
            DT="검사 대상: /tmp, /var/tmp
    숨김 파일/디렉토리: 없음"
        else
            typeset COUNT=0
            if [ -n "$ALL_HIDDEN" ]; then
                COUNT=$(echo "$ALL_HIDDEN" | wc -l | tr -d ' ')
            fi
            RES="M"
            DESC="숨김 파일/디렉토리 ${COUNT}개 수동 확인 필요"
            DT="검사 대상: /tmp, /var/tmp
    숨김 파일/디렉토리 (상위 20개):
    $ALL_HIDDEN"
        fi

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

        # inetd.conf에서 finger 서비스 확인
        if is_inetd_service_enabled "finger"; then
            RUNNING="true"
            DETAILS="inetd.conf: finger 서비스 활성화"
        fi

        # finger 프로세스 확인
        if is_process_running "fingerd"; then
            RUNNING="true"
            DETAILS="${DETAILS}
    fingerd 프로세스: 실행 중"
        fi

        # 포트 79 확인
        typeset PORT79=""
        PORT79=$(netstat -an 2>/dev/null | grep "\.79 " | grep -i listen)
        if [ -n "$PORT79" ]; then
            RUNNING="true"
            DETAILS="${DETAILS}
    포트 79: 사용 중
    $PORT79"
        fi

        if [ "$RUNNING" = "true" ]; then
            RES="N"
            DESC="Finger 서비스가 활성화되어 있음"
        else
            RES="Y"
            DESC="Finger 서비스가 비활성화됨"
            DETAILS="fingerd: 미실행
    inetd.conf: finger 비활성"
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

        # FTP 익명 계정 확인
        typeset FTP_ANON=""
        FTP_ANON=$(grep -E "^(ftp|anonymous):" /etc/passwd 2>/dev/null)
        if [ -n "$FTP_ANON" ]; then
            VULNERABLE="true"
            DETAILS="FTP 익명 계정 존재:
    $FTP_ANON"
        fi

        # vsftpd 설정 확인
        if [ -f /etc/vsftpd.conf ]; then
            typeset ANON_ENABLE=""
            ANON_ENABLE=$(grep -i "^anonymous_enable" /etc/vsftpd.conf 2>/dev/null)
            if [ -n "$ANON_ENABLE" ]; then
                typeset ANON_VAL=""
                ANON_VAL=$(echo "$ANON_ENABLE" | tr -d ' ' | cut -d= -f2)
                ANON_VAL=$(to_upper "$ANON_VAL")
                if [ "$ANON_VAL" = "YES" ]; then
                    VULNERABLE="true"
                    DETAILS="${DETAILS}
    vsftpd anonymous_enable=YES"
                fi
            fi
        fi

        # NFS exports 확인
        if [ -f /etc/exports ]; then
            typeset EXPORTS=""
            EXPORTS=$(grep -v "^#" /etc/exports 2>/dev/null | grep -v "^$")
            if [ -n "$EXPORTS" ]; then
                DETAILS="${DETAILS}
    NFS exports:
    $EXPORTS"
                typeset ANON_NFS=""
                ANON_NFS=$(echo "$EXPORTS" | grep "anon" | grep -v "anon=-1")
                if [ -n "$ANON_NFS" ]; then
                    VULNERABLE="true"
                    DETAILS="${DETAILS}
    NFS 익명 접근 허용(anon !=-1)"
                fi
            fi
        fi

        # Samba 확인 (AIX: /usr/lib/smb.conf)
        typeset SMB_CONF=""
        for f in /usr/lib/smb.conf /etc/samba/smb.conf; do
            if [ -f "$f" ]; then
                SMB_CONF="$f"
                break
            fi
        done
        if [ -n "$SMB_CONF" ]; then
            typeset GUEST_OK=""
            GUEST_OK=$(grep -i "guest ok" "$SMB_CONF" 2>/dev/null | grep -i "yes")
            if [ -n "$GUEST_OK" ]; then
                VULNERABLE="true"
                DETAILS="${DETAILS}
    Samba guest ok = yes ($SMB_CONF)"
            fi
        fi

        if [ "$VULNERABLE" = "true" ]; then
            RES="N"
            DESC="공유 서비스에 익명 접근이 허용되어 있음"
        else
            RES="Y"
            DESC="공유 서비스에 익명 접근이 제한됨"
            if [ -z "$DETAILS" ]; then
                DETAILS="공유 서비스 익명 접근: 미발견"
            fi
        fi

        DT="$DETAILS"

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

        # inetd.conf에서 r 계열 서비스 확인 (login=rlogin, shell=rsh, exec=rexec)
        for svc in login shell exec; do
            if is_inetd_service_enabled "$svc"; then
                RUNNING="${RUNNING}${svc} "
                DETAILS="${DETAILS}
    inetd.conf: ${svc} 활성화"
            fi
        done

        # r 계열 프로세스 확인
        for proc in rlogind rshd rexecd; do
            if is_process_running "$proc"; then
                RUNNING="${RUNNING}${proc} "
                DETAILS="${DETAILS}
    ${proc} 프로세스: 실행 중"
            fi
        done

        # r 계열 포트 확인 (512=exec, 513=login, 514=shell)
        typeset RPORTS=""
        RPORTS=$(netstat -an 2>/dev/null | grep -E "\.51[234] " | grep -i listen)
        if [ -n "$RPORTS" ]; then
            DETAILS="${DETAILS}
    r 계열 포트:
    $RPORTS"
        fi

        if [ -n "$RUNNING" ]; then
            RES="N"
            DESC="r 계열 서비스가 활성화되어 있음"
        else
            RES="Y"
            DESC="r 계열 서비스가 비활성화됨"
            DETAILS="r 계열 서비스(login, shell, exec): 비활성"
        fi

        DT="$DETAILS"

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

        # AIX crontab 명령어 권한 확인 (750 이하)
        typeset CMD_TARGETS="/usr/bin/crontab /usr/bin/at"
        for target in $CMD_TARGETS; do
            if [ -f "$target" ]; then
                typeset PERM=""
                PERM=$(get_file_perm "$target")
                typeset OWNER=""
                OWNER=$(get_file_owner "$target")
                DETAILS="${DETAILS}
    ${target}: owner=${OWNER}, perm=${PERM}"
                if [ "$OWNER" != "root" ]; then
                    VULNERABLE="${VULNERABLE}${target}(owner=${OWNER}) "
                fi
            fi
        done

        # AIX cron 관련 파일 확인 (640 이하)
        # AIX: /var/adm/cron/cron.allow, /var/adm/cron/cron.deny, /var/adm/cron/at.allow, /var/adm/cron/at.deny
        typeset FILE_TARGETS="/var/adm/cron/cron.allow /var/adm/cron/cron.deny /var/adm/cron/at.allow /var/adm/cron/at.deny"
        for target in $FILE_TARGETS; do
            if [ -f "$target" ]; then
                typeset PERM=""
                PERM=$(get_file_perm "$target")
                typeset OWNER=""
                OWNER=$(get_file_owner "$target")
                DETAILS="${DETAILS}
    ${target}: owner=${OWNER}, perm=${PERM}"
                if [ "$OWNER" != "root" ]; then
                    VULNERABLE="${VULNERABLE}${target}(owner=${OWNER}) "
                fi
                # 640 이하인지 확인
                typeset U_PERM=""
                typeset G_PERM=""
                typeset O_PERM=""
                U_PERM=$(echo "$PERM" | cut -c1)
                G_PERM=$(echo "$PERM" | cut -c2)
                O_PERM=$(echo "$PERM" | cut -c3)
                if [ "$O_PERM" -gt 0 ] 2>/dev/null; then
                    VULNERABLE="${VULNERABLE}${target}(perm=${PERM}) "
                fi
                if [ "$G_PERM" -gt 4 ] 2>/dev/null; then
                    VULNERABLE="${VULNERABLE}${target}(group=${G_PERM}) "
                fi
            fi
        done

        # crontab 작업 디렉토리 확인
        typeset CRON_SPOOL="/var/spool/cron/crontabs"
        if [ -d "$CRON_SPOOL" ]; then
            typeset SPOOL_PERM=""
            SPOOL_PERM=$(get_file_perm "$CRON_SPOOL")
            typeset SPOOL_OWNER=""
            SPOOL_OWNER=$(get_file_owner "$CRON_SPOOL")
            DETAILS="${DETAILS}
    ${CRON_SPOOL}: owner=${SPOOL_OWNER}, perm=${SPOOL_PERM}"
        fi

        if [ -z "$VULNERABLE" ]; then
            RES="Y"
            DESC="crontab 및 at 관련 파일 권한이 양호함"
        else
            RES="N"
            DESC="crontab 또는 at 관련 파일 권한이 부적절함"
        fi

        DT="$DETAILS
    취약: ${VULNERABLE:-없음}"

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

    typeset VULNERABLE_SVCS="echo discard daytime chargen"
    typeset RUNNING=""
    typeset DETAILS=""

    # inetd.conf에서 DoS 취약 서비스 확인
    for svc in $VULNERABLE_SVCS; do
        if is_inetd_service_enabled "$svc"; then
            RUNNING="${RUNNING}${svc} "
        fi
    done

    if [ -n "$RUNNING" ]; then
        DETAILS="inetd.conf 활성화 서비스: $RUNNING"
    fi

    if [ -z "$RUNNING" ]; then
        RES="Y"
        DESC="DoS 취약 서비스가 비활성화됨"
        DT="echo, discard, daytime, chargen: 비활성"
    else
        RES="N"
        DESC="DoS 취약 서비스가 활성화되어 있음"
        DT="$DETAILS"
    fi

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

        # AIX: lssrc -g nfs 로 NFS 서비스 그룹 확인
        typeset NFS_SRC=""
        NFS_SRC=$(lssrc -g nfs 2>/dev/null | grep -i "active")
        if [ -n "$NFS_SRC" ]; then
            RUNNING="true"
            DETAILS="NFS 서비스 그룹(active):
    $NFS_SRC"
        fi

        # nfsd 프로세스 확인
        if is_process_running "nfsd"; then
            RUNNING="true"
            DETAILS="${DETAILS}
    nfsd 프로세스: 실행 중"
        fi

        # 포트 2049 확인
        typeset PORT2049=""
        PORT2049=$(netstat -an 2>/dev/null | grep "\.2049 " | grep -i listen)
        if [ -n "$PORT2049" ]; then
            RUNNING="true"
            DETAILS="${DETAILS}
    포트 2049: 사용 중
    $PORT2049"
        fi

        if [ "$RUNNING" = "true" ]; then
            RES="M"
            DESC="NFS 서비스 사용 여부 수동 확인 필요"
        else
            RES="Y"
            DESC="NFS 서비스가 비활성화됨"
            DETAILS="NFS: 미실행"
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

        typeset EXPORTS_FILE="/etc/exports"

        if [ ! -f "$EXPORTS_FILE" ]; then
            RES="N/A"
            DESC="NFS exports 파일이 존재하지 않음"
            DT="${EXPORTS_FILE}: 없음"
        else
            typeset PERM=""
            PERM=$(get_file_perm "$EXPORTS_FILE")
            typeset OWNER=""
            OWNER=$(get_file_owner "$EXPORTS_FILE")

            typeset EXPORTS=""
            EXPORTS=$(grep -v "^#" "$EXPORTS_FILE" 2>/dev/null | grep -v "^$")

            if [ -z "$EXPORTS" ]; then
                RES="Y"
                DESC="NFS 공유 설정이 없음"
                DT="${EXPORTS_FILE}: owner=${OWNER}, perm=${PERM}
    내용: 비어있음"
            else
                typeset VULN="false"
                typeset VULN_DETAIL=""

                # 파일 권한 644 초과 확인
                typeset O_PERM=""
                O_PERM=$(echo "$PERM" | cut -c3)
                if [ "$O_PERM" -gt 4 ] 2>/dev/null; then
                    VULN="true"
                    VULN_DETAIL="파일 권한 ${PERM}이 644 초과"
                fi

                # 소유자 확인
                if [ "$OWNER" != "root" ]; then
                    VULN="true"
                    VULN_DETAIL="${VULN_DETAIL}
    소유자가 root가 아님(${OWNER})"
                fi

                # everyone 접근(*) 확인
                typeset EVERYONE=""
                EVERYONE=$(echo "$EXPORTS" | grep "\*")
                if [ -n "$EVERYONE" ]; then
                    VULN="true"
                    VULN_DETAIL="${VULN_DETAIL}
    모든 호스트 접근 허용(*) 설정 존재"
                fi

                if [ "$VULN" = "true" ]; then
                    RES="N"
                    DESC="NFS 접근 통제가 미흡함"
                else
                    RES="M"
                    DESC="NFS 접근 통제 설정 수동 확인 필요"
                fi

                DT="${EXPORTS_FILE}: owner=${OWNER}, perm=${PERM}
    내용:
    $EXPORTS
    ${VULN_DETAIL}"
            fi
        fi

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

        # AIX: SRC로 automountd 서비스 확인
        if is_service_active "automountd"; then
            RUNNING="true"
            DETAILS="automountd SRC 서비스: active"
        fi

        # autofs SRC 확인
        if is_service_active "autofs"; then
            RUNNING="true"
            DETAILS="${DETAILS}
    autofs SRC 서비스: active"
        fi

        # automountd 프로세스 확인
        if is_process_running "automountd"; then
            RUNNING="true"
            DETAILS="${DETAILS}
    automountd 프로세스: 실행 중"
        fi

        if [ "$RUNNING" = "true" ]; then
            RES="N"
            DESC="automountd 서비스가 실행 중임"
        else
            RES="Y"
            DESC="automountd 서비스가 비활성화됨"
            DETAILS="automountd: 미실행
    autofs: 미실행"
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

        typeset RPC_SVCS="rpc.cmsd rpc.ttdbserverd sadmind rusersd walld sprayd rstatd rpc.nisd rexd rpc.pcnfsd rpc.statd rpc.ypupdated rpc.rquotad kcms_server cachefsd"
        typeset RUNNING=""
        typeset DETAILS=""

        # inetd.conf에서 RPC 서비스 확인
        typeset INETD_RPC=""
        if [ -f "$INETD_CONF" ]; then
            INETD_RPC=$(grep -v "^#" "$INETD_CONF" 2>/dev/null | grep -iE "rexd|rstatd|rusersd|sprayd|walld|rquotad|cmsd|ttdbserverd|sadmind|pcnfsd|ypupdated|cachefsd|kcms_server")
            if [ -n "$INETD_RPC" ]; then
                DETAILS="inetd.conf RPC 서비스:
    $INETD_RPC"
                RUNNING="Y"
            fi
        fi

        # 프로세스 확인
        for svc in $RPC_SVCS; do
            if is_process_running "$svc"; then
                RUNNING="Y"
                DETAILS="${DETAILS}
    ${svc} 프로세스: 실행 중"
            fi
        done

        if [ -z "$RUNNING" ]; then
            RES="Y"
            DESC="불필요한 RPC 서비스가 비활성화됨"
            DT="취약 RPC 서비스: 미실행"
        else
            RES="N"
            DESC="불필요한 RPC 서비스가 활성화되어 있음"
            DT="$DETAILS"
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

        # AIX: SRC로 NIS 서비스 확인
        typeset NIS_SVCS="ypserv ypbind yppasswdd ypxfrd ypupdated"
        for svc in $NIS_SVCS; do
            if is_service_active "$svc"; then
                RUNNING="true"
                DETAILS="${DETAILS}
    ${svc} SRC: active"
            fi
        done

        # NIS 프로세스 확인
        for proc in ypserv ypbind rpc.yppasswdd rpc.ypupdated ypxfrd; do
            if is_process_running "$proc"; then
                RUNNING="true"
                DETAILS="${DETAILS}
    ${proc} 프로세스: 실행 중"
            fi
        done

        if [ "$RUNNING" = "true" ]; then
            RES="N"
            DESC="NIS 서비스가 활성화되어 있음"
        else
            RES="Y"
            DESC="NIS 서비스가 비활성화됨"
            DETAILS="NIS 관련 서비스: 미실행"
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
        for svc in tftp talk ntalk; do
            if is_inetd_service_enabled "$svc"; then
                RUNNING="${RUNNING}${svc} "
                DETAILS="${DETAILS}
    inetd.conf: ${svc} 활성화"
            fi
        done

        # 프로세스 확인
        for proc in tftpd in.tftpd talkd in.talkd; do
            if is_process_running "$proc"; then
                RUNNING="${RUNNING}${proc} "
                DETAILS="${DETAILS}
    ${proc} 프로세스: 실행 중"
            fi
        done

        # 포트 확인 (69=tftp, 517=talk, 518=ntalk)
        typeset PORT_CHECK=""
        PORT_CHECK=$(netstat -an 2>/dev/null | grep -E "\.69 |\.517 |\.518 ")
        if [ -n "$PORT_CHECK" ]; then
            DETAILS="${DETAILS}
    관련 포트:
    $PORT_CHECK"
        fi

        if [ -z "$RUNNING" ]; then
            RES="Y"
            DESC="tftp, talk, ntalk 서비스가 비활성화됨"
            DT="tftp, talk, ntalk: 비활성"
        else
            RES="N"
            DESC="tftp, talk 또는 ntalk 서비스가 활성화됨"
            DT="$DETAILS"
        fi

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

        # AIX: Sendmail 확인 (lssrc -s sendmail)
        if is_service_active "sendmail"; then
            MAIL_FOUND="true"
            typeset SM_VER=""
            SM_VER=$(sendmail -d0.1 -bv root 2>&1 | head -1)
            DETAILS="sendmail SRC: active
    sendmail 버전: ${SM_VER:-확인불가}"
        elif is_process_running "sendmail"; then
            MAIL_FOUND="true"
            typeset SM_VER=""
            SM_VER=$(sendmail -d0.1 -bv root 2>&1 | head -1)
            DETAILS="sendmail 프로세스: 실행 중
    sendmail 버전: ${SM_VER:-확인불가}"
        fi

        # Postfix 확인
        if is_process_running "master"; then
            typeset PF_CHECK=""
            PF_CHECK=$(ps -ef 2>/dev/null | grep "postfix" | grep -v grep)
            if [ -n "$PF_CHECK" ]; then
                MAIL_FOUND="true"
                typeset PF_VER=""
                PF_VER=$(postconf mail_version 2>/dev/null | cut -d= -f2)
                DETAILS="${DETAILS}
    postfix 프로세스: 실행 중
    postfix 버전: ${PF_VER:-확인불가}"
            fi
        fi

        # Exim 확인
        if is_process_running "exim"; then
            MAIL_FOUND="true"
            typeset EX_VER=""
            EX_VER=$(exim -bV 2>/dev/null | head -1)
            DETAILS="${DETAILS}
    exim 프로세스: 실행 중
    exim 버전: ${EX_VER:-확인불가}"
        fi

        if [ "$MAIL_FOUND" = "true" ]; then
            RES="M"
            DESC="메일 서비스 버전 수동 확인 필요"
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

        typeset SENDMAIL_CF="/etc/mail/sendmail.cf"
        typeset MAIL_RUNNING="false"
        typeset HAS_ISSUE="false"
        typeset DETAILS=""

        # sendmail 실행 여부 확인
        if is_service_active "sendmail" || is_process_running "sendmail"; then
            MAIL_RUNNING="true"
        fi

        if [ "$MAIL_RUNNING" = "false" ]; then
            # postfix 확인
            if is_process_running "master"; then
                typeset PF_CHECK=""
                PF_CHECK=$(ps -ef 2>/dev/null | grep "postfix" | grep -v grep)
                if [ -n "$PF_CHECK" ]; then
                    MAIL_RUNNING="true"
                    # postsuper 실행 권한 확인
                    if [ -f /usr/sbin/postsuper ]; then
                        typeset PS_PERM=""
                        PS_PERM=$(get_file_perm "/usr/sbin/postsuper")
                        typeset O_PERM=""
                        O_PERM=$(echo "$PS_PERM" | cut -c3)
                        DETAILS="postfix 실행 중
    /usr/sbin/postsuper: perm=${PS_PERM}"
                        if echo "$O_PERM" | grep -q "[1357]"; then
                            HAS_ISSUE="true"
                            DETAILS="${DETAILS}
    postsuper other 실행 권한: 존재(취약)"
                        else
                            DETAILS="${DETAILS}
    postsuper other 실행 권한: 없음(양호)"
                        fi
                    fi
                fi
            fi
        fi

        if [ "$MAIL_RUNNING" = "true" ] && [ -z "$DETAILS" ]; then
            # sendmail.cf PrivacyOptions 확인
            if [ -f "$SENDMAIL_CF" ]; then
                typeset PRIVACY=""
                PRIVACY=$(grep -i "^O PrivacyOptions" "$SENDMAIL_CF" 2>/dev/null)
                DETAILS="sendmail 실행 중
    sendmail.cf: ${PRIVACY:-설정없음}"
                typeset HAS_RESTRICT=""
                HAS_RESTRICT=$(echo "$PRIVACY" | grep -i "restrictqrun")
                if [ -n "$HAS_RESTRICT" ]; then
                    DETAILS="${DETAILS}
    restrictqrun: 설정됨(양호)"
                else
                    HAS_ISSUE="true"
                    DETAILS="${DETAILS}
    restrictqrun: 미설정(취약)"
                fi
            else
                DETAILS="sendmail 실행 중
    ${SENDMAIL_CF}: 파일 없음"
                HAS_ISSUE="true"
            fi
        fi

        if [ "$MAIL_RUNNING" = "false" ]; then
            RES="N/A"
            DESC="메일 서비스가 실행되지 않음"
            DT="sendmail/postfix: 미실행"
        elif [ "$HAS_ISSUE" = "true" ]; then
            RES="N"
            DESC="일반 사용자의 메일 서비스 실행 방지가 미설정됨"
            DT="$DETAILS"
        else
            RES="Y"
            DESC="일반 사용자의 메일 서비스 실행 방지가 설정됨"
            DT="$DETAILS"
        fi

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
        typeset MAIL_RUNNING="false"

        # sendmail 실행 여부 확인
        if is_service_active "sendmail" || is_process_running "sendmail"; then
            MAIL_RUNNING="true"
        fi

        if [ "$MAIL_RUNNING" = "false" ]; then
            # postfix 확인
            typeset PF_CHECK=""
            PF_CHECK=$(ps -ef 2>/dev/null | grep "postfix" | grep -v grep)
            if [ -n "$PF_CHECK" ]; then
                MAIL_RUNNING="true"
            fi
        fi

        if [ "$MAIL_RUNNING" = "false" ]; then
            RES="N/A"
            DESC="메일 서비스가 실행되지 않음"
            DT="sendmail/postfix: 미실행"
        else
            # sendmail.cf 확인
            if [ -f /etc/mail/sendmail.cf ]; then
                typeset RELAY=""
                RELAY=$(grep -i "R\$\*" /etc/mail/sendmail.cf 2>/dev/null | head -3)
                typeset PROMISC=""
                PROMISC=$(grep -i "promiscuous_relay" /etc/mail/sendmail.cf 2>/dev/null)
                DETAILS="sendmail.cf 릴레이 설정:
    ${RELAY:-설정없음}"
                if [ -n "$PROMISC" ]; then
                    DETAILS="${DETAILS}
    promiscuous_relay 설정 발견(취약)"
                    RES="N"
                    DESC="메일 릴레이가 무제한 허용되어 있음"
                else
                    RES="M"
                    DESC="메일 릴레이 설정 수동 확인 필요"
                fi
            elif [ -f /etc/postfix/main.cf ]; then
                typeset PF_RELAY=""
                PF_RELAY=$(grep -iE "mynetworks|relay" /etc/postfix/main.cf 2>/dev/null | grep -v "^#" | head -5)
                DETAILS="postfix 릴레이 설정:
    ${PF_RELAY:-설정없음}"
                RES="M"
                DESC="메일 릴레이 설정 수동 확인 필요"
            else
                RES="M"
                DESC="메일 설정 파일 수동 확인 필요"
                DETAILS="메일 서비스 실행 중이나 설정 파일 미발견"
            fi
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
        typeset MAIL_RUNNING="false"

        # sendmail 실행 여부 확인
        if is_service_active "sendmail" || is_process_running "sendmail"; then
            MAIL_RUNNING="true"
        fi

        if [ "$MAIL_RUNNING" = "false" ]; then
            # postfix 확인
            typeset PF_CHECK=""
            PF_CHECK=$(ps -ef 2>/dev/null | grep "postfix" | grep -v grep)
            if [ -n "$PF_CHECK" ]; then
                MAIL_RUNNING="true"
            fi
        fi

        if [ "$MAIL_RUNNING" = "false" ]; then
            RES="N/A"
            DESC="메일 서비스가 실행되지 않음"
            DT="sendmail/postfix: 미실행"
        else
            # sendmail.cf 확인
            if [ -f /etc/mail/sendmail.cf ]; then
                typeset PRIVACY=""
                PRIVACY=$(grep -i "^O PrivacyOptions" /etc/mail/sendmail.cf 2>/dev/null)
                DETAILS="sendmail.cf PrivacyOptions:
    ${PRIVACY:-설정없음}"

                typeset HAS_NOEXPN=""
                HAS_NOEXPN=$(echo "$PRIVACY" | grep -i "noexpn")
                typeset HAS_NOVRFY=""
                HAS_NOVRFY=$(echo "$PRIVACY" | grep -i "novrfy")
                typeset HAS_GOAWAY=""
                HAS_GOAWAY=$(echo "$PRIVACY" | grep -i "goaway")

                if [ -n "$HAS_GOAWAY" ] || { [ -n "$HAS_NOEXPN" ] && [ -n "$HAS_NOVRFY" ]; }; then
                    RES="Y"
                    DESC="expn, vrfy 명령어가 제한됨"
                else
                    RES="N"
                    DESC="expn 또는 vrfy 명령어 제한이 미설정됨"
                fi
            elif [ -f /etc/postfix/main.cf ]; then
                typeset VRFY=""
                VRFY=$(grep -i "disable_vrfy_command" /etc/postfix/main.cf 2>/dev/null | grep -v "^#")
                DETAILS="postfix disable_vrfy_command:
    ${VRFY:-설정없음}"

                typeset VRFY_YES=""
                VRFY_YES=$(echo "$VRFY" | grep -i "yes")
                if [ -n "$VRFY_YES" ]; then
                    RES="Y"
                    DESC="vrfy 명령어가 제한됨"
                else
                    RES="N"
                    DESC="vrfy 명령어 제한이 미설정됨"
                fi
            else
                RES="M"
                DESC="메일 설정 파일 수동 확인 필요"
                DETAILS="메일 서비스 실행 중이나 설정 파일 미발견"
            fi
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
        typeset DNS_RUNNING="false"

        # AIX: SRC로 named 서비스 확인
        if is_service_active "named"; then
            DNS_RUNNING="true"
            DETAILS="named SRC 서비스: active"
        fi

        # named 프로세스 확인
        if is_process_running "named"; then
            DNS_RUNNING="true"
            DETAILS="${DETAILS}
    named 프로세스: 실행 중"
        fi

        if [ "$DNS_RUNNING" = "true" ]; then
            # BIND 버전 확인
            typeset NAMED_VER=""
            NAMED_VER=$(named -v 2>/dev/null)
            if [ -n "$NAMED_VER" ]; then
                DETAILS="${DETAILS}
    BIND 버전: $NAMED_VER"
            else
                DETAILS="${DETAILS}
    BIND 버전: 확인불가"
            fi
            RES="M"
            DESC="DNS 서비스 버전 수동 확인 필요"
        else
            RES="N/A"
            DESC="DNS 서비스가 실행되지 않음"
            DETAILS="named: 미실행"
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
        typeset DNS_RUNNING="false"

        # AIX: named 서비스 확인
        if is_service_active "named" || is_process_running "named"; then
            DNS_RUNNING="true"
        fi

        if [ "$DNS_RUNNING" = "false" ]; then
            RES="N/A"
            DESC="DNS 서비스가 실행되지 않음"
            DT="named: 미실행"
        else
            # named.conf 파일 확인 (AIX 가능 경로)
            typeset NAMED_CONF=""
            for f in /etc/named.conf /etc/bind/named.conf /etc/named.boot /etc/bind/named.boot; do
                if [ -f "$f" ]; then
                    NAMED_CONF="$f"
                    break
                fi
            done

            if [ -z "$NAMED_CONF" ]; then
                RES="M"
                DESC="DNS 설정 파일을 찾을 수 없어 수동 확인 필요"
                DT="named.conf/named.boot: 없음"
            else
                typeset ALLOW_TRANSFER=""
                ALLOW_TRANSFER=$(grep -i "allow-transfer" "$NAMED_CONF" 2>/dev/null)
                typeset XFRNETS=""
                XFRNETS=$(grep -i "xfrnets" "$NAMED_CONF" 2>/dev/null)

                DETAILS="설정 파일: $NAMED_CONF"

                if [ -n "$ALLOW_TRANSFER" ]; then
                    DETAILS="${DETAILS}
    allow-transfer: $ALLOW_TRANSFER"
                    typeset HAS_NONE=""
                    HAS_NONE=$(echo "$ALLOW_TRANSFER" | grep -i "none")
                    typeset HAS_ANY=""
                    HAS_ANY=$(echo "$ALLOW_TRANSFER" | grep -i "any")
                    if [ -n "$HAS_NONE" ]; then
                        RES="Y"
                        DESC="Zone Transfer가 none으로 제한됨"
                    elif [ -n "$HAS_ANY" ]; then
                        RES="N"
                        DESC="Zone Transfer가 모든 사용자에게 허용됨"
                    else
                        RES="M"
                        DESC="Zone Transfer 설정 수동 확인 필요"
                    fi
                elif [ -n "$XFRNETS" ]; then
                    DETAILS="${DETAILS}
    xfrnets: $XFRNETS"
                    RES="M"
                    DESC="Zone Transfer xfrnets 설정 수동 확인 필요"
                else
                    RES="N"
                    DESC="Zone Transfer 제한이 설정되어 있지 않음"
                    DETAILS="${DETAILS}
    allow-transfer: 미설정
    xfrnets: 미설정"
                fi
            fi
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

        # inetd.conf에서 telnet 서비스 확인
        if is_inetd_service_enabled "telnet"; then
            RUNNING="true"
            DETAILS="inetd.conf: telnet 서비스 활성화"
        fi

        # telnetd 프로세스 확인
        if is_process_running "telnetd"; then
            RUNNING="true"
            DETAILS="${DETAILS}
    telnetd 프로세스: 실행 중"
        fi

        # 포트 23 확인
        typeset PORT23=""
        PORT23=$(netstat -an 2>/dev/null | grep "\.23 " | grep -i listen)
        if [ -n "$PORT23" ]; then
            RUNNING="true"
            DETAILS="${DETAILS}
    포트 23: 사용 중
    $PORT23"
        fi

        if [ "$RUNNING" = "true" ]; then
            RES="N"
            DESC="Telnet 서비스가 활성화됨"
        else
            RES="Y"
            DESC="Telnet 서비스가 비활성화됨"
            DETAILS="telnet: 미실행
    inetd.conf: telnet 비활성"
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
        typeset FTP_FOUND="false"

        # AIX 기본 FTP 배너 카탈로그 확인
        typeset FTP_CAT="/usr/lib/nls/msg/en_US/ftpd.cat"
        if [ -f "$FTP_CAT" ]; then
            FTP_FOUND="true"
            DETAILS="AIX 기본 FTP 배너 카탈로그: $FTP_CAT 존재"
        fi

        # vsftpd 확인
        if [ -f /etc/vsftpd.conf ]; then
            FTP_FOUND="true"
            typeset BANNER=""
            BANNER=$(grep -i "ftpd_banner" /etc/vsftpd.conf 2>/dev/null)
            DETAILS="${DETAILS}
    vsftpd 배너: ${BANNER:-기본값}"
        fi

        # proftpd 확인
        if [ -f /etc/proftpd.conf ]; then
            FTP_FOUND="true"
            typeset IDENT=""
            IDENT=$(grep -i "ServerIdent" /etc/proftpd.conf 2>/dev/null)
            DETAILS="${DETAILS}
    proftpd ServerIdent: ${IDENT:-기본값}"
        fi

        if [ "$FTP_FOUND" = "true" ]; then
            RES="M"
            DESC="FTP 배너 설정 수동 확인 필요"
        else
            RES="N/A"
            DESC="FTP 서비스 설정 파일 없음"
            DETAILS="FTP 설정 파일: 없음"
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

        # inetd.conf에서 FTP 서비스 확인
        if is_inetd_service_enabled "ftp"; then
            RUNNING="true"
            DETAILS="inetd.conf: ftp 서비스 활성화"
        fi

        # FTP 프로세스 확인
        if is_process_running "ftpd"; then
            RUNNING="true"
            DETAILS="${DETAILS}
    ftpd 프로세스: 실행 중"
        fi
        if is_process_running "vsftpd"; then
            RUNNING="true"
            DETAILS="${DETAILS}
    vsftpd 프로세스: 실행 중"
        fi
        if is_process_running "proftpd"; then
            RUNNING="true"
            DETAILS="${DETAILS}
    proftpd 프로세스: 실행 중"
        fi

        # 포트 21 확인
        typeset PORT21=""
        PORT21=$(netstat -an 2>/dev/null | grep "\.21 " | grep -i listen)
        if [ -n "$PORT21" ]; then
            RUNNING="true"
            DETAILS="${DETAILS}
    포트 21: 사용 중
    $PORT21"
        fi

        if [ "$RUNNING" = "true" ]; then
            # SSL/TLS 설정 확인
            if [ -f /etc/vsftpd.conf ]; then
                typeset SSL_EN=""
                SSL_EN=$(grep -i "ssl_enable=YES" /etc/vsftpd.conf 2>/dev/null)
                if [ -n "$SSL_EN" ]; then
                    RES="Y"
                    DESC="FTP SSL/TLS가 활성화됨"
                else
                    RES="N"
                    DESC="FTP가 암호화 없이 실행 중"
                fi
            else
                RES="N"
                DESC="암호화되지 않은 FTP 서비스가 활성화됨"
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
            *nologin*|*false*)
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

        # /etc/ftpd/ftpusers 또는 /etc/ftpusers 확인
        if [ -f /etc/ftpd/ftpusers ]; then
            HAS_CONTROL="true"
            DETAILS="ftpusers: /etc/ftpd/ftpusers 존재"
        elif [ -f /etc/ftpusers ]; then
            HAS_CONTROL="true"
            DETAILS="ftpusers: /etc/ftpusers 존재"
        fi

        # hosts.allow/deny 확인
        if [ -f /etc/hosts.allow ]; then
            typeset ALLOW_FTP=""
            ALLOW_FTP=$(grep -i "ftpd" /etc/hosts.allow 2>/dev/null)
            if [ -n "$ALLOW_FTP" ]; then
                HAS_CONTROL="true"
                DETAILS="${DETAILS}
    hosts.allow: FTP 설정 존재"
            fi
        fi

        if [ -f /etc/hosts.deny ]; then
            typeset DENY_FTP=""
            DENY_FTP=$(grep -i "ftpd" /etc/hosts.deny 2>/dev/null)
            if [ -n "$DENY_FTP" ]; then
                HAS_CONTROL="true"
                DETAILS="${DETAILS}
    hosts.deny: FTP 설정 존재"
            fi
        fi

        # vsftpd tcp_wrappers 확인
        if [ -f /etc/vsftpd.conf ]; then
            typeset TCP_WRAP=""
            TCP_WRAP=$(grep -i "tcp_wrappers" /etc/vsftpd.conf 2>/dev/null)
            DETAILS="${DETAILS}
    vsftpd tcp_wrappers: ${TCP_WRAP:-not set}"
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
        if [ -f /etc/ftpd/ftpusers ]; then
            FTPUSERS="/etc/ftpd/ftpusers"
        elif [ -f /etc/ftpusers ]; then
            FTPUSERS="/etc/ftpusers"
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

        # lssrc로 snmpd 서비스 확인
        if is_service_active "snmpd"; then
            RUNNING="true"
            DETAILS="lssrc -s snmpd: active"
        fi

        # snmpd 프로세스 확인
        if is_process_running "snmpd"; then
            RUNNING="true"
            DETAILS="${DETAILS}
    snmpd 프로세스: 실행 중"
        fi

        # 포트 161 확인
        typeset PORT161=""
        PORT161=$(netstat -an 2>/dev/null | grep "\.161 " | grep -i listen)
        if [ -n "$PORT161" ]; then
            RUNNING="true"
            DETAILS="${DETAILS}
    포트 161: 사용 중
    $PORT161"
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

        typeset SNMP_CONF="/etc/snmpdv3.conf"
        typeset SNMP_CONF2="/etc/snmp/snmpd.conf"

        # AIX uses /etc/snmpdv3.conf primarily
        typeset CONF_FILE=""
        if [ -f "$SNMP_CONF" ]; then
            CONF_FILE="$SNMP_CONF"
        elif [ -f "$SNMP_CONF2" ]; then
            CONF_FILE="$SNMP_CONF2"
        fi

        if [ -z "$CONF_FILE" ]; then
            typeset SNMPD_RUNNING="false"
            if is_process_running "snmpd"; then
                SNMPD_RUNNING="true"
            fi
            if [ "$SNMPD_RUNNING" = "true" ]; then
                RES="M"
                DESC="SNMP 설정 수동 확인 필요"
                DT="설정 파일: 없음, snmpd: 실행 중"
            else
                RES="N/A"
                DESC="SNMP 서비스가 사용되지 않음"
                DT="설정 파일: 없음, snmpd: 미실행"
            fi
        else
            typeset V3_CONFIG=""
            V3_CONFIG=$(grep -iE "^rouser|^rwuser|^createUser|^USM_USER" "$CONF_FILE" 2>/dev/null)
            typeset V1V2_CONFIG=""
            V1V2_CONFIG=$(grep -iE "^rocommunity|^rwcommunity|^COMMUNITY" "$CONF_FILE" 2>/dev/null)

            if [ -n "$V3_CONFIG" ] && [ -z "$V1V2_CONFIG" ]; then
                RES="Y"
                DESC="SNMPv3만 사용 중"
                DT="설정 파일: $CONF_FILE
    SNMPv3 설정:
    $V3_CONFIG"
            elif [ -n "$V1V2_CONFIG" ]; then
                RES="N"
                DESC="취약한 SNMP 버전(v1/v2c) 사용 중"
                DT="설정 파일: $CONF_FILE
    v1/v2c 설정:
    $V1V2_CONFIG"
            else
                RES="M"
                DESC="SNMP 버전 수동 확인 필요"
                DT="설정 파일: $CONF_FILE
    설정 확인 필요"
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

        # AIX uses /etc/snmpdv3.conf
        typeset SNMP_CONF="/etc/snmpdv3.conf"
        typeset SNMP_CONF2="/etc/snmp/snmpd.conf"
        typeset WEAK_STRINGS="public private"

        typeset CONF_FILE=""
        if [ -f "$SNMP_CONF" ]; then
            CONF_FILE="$SNMP_CONF"
        elif [ -f "$SNMP_CONF2" ]; then
            CONF_FILE="$SNMP_CONF2"
        fi

        if [ -z "$CONF_FILE" ]; then
            RES="N/A"
            DESC="SNMP 설정 파일이 없음"
            DT="snmpd 설정 파일: 없음"
        else
            # AIX snmpdv3.conf uses COMMUNITY keyword
            typeset COMMUNITIES=""
            if [ "$CONF_FILE" = "$SNMP_CONF" ]; then
                COMMUNITIES=$(grep -i "^COMMUNITY" "$CONF_FILE" 2>/dev/null | awk '{print $2}')
            else
                COMMUNITIES=$(grep -iE "^rocommunity|^rwcommunity" "$CONF_FILE" 2>/dev/null | awk '{print $2}')
            fi

            typeset HAS_WEAK="false"
            typeset comm=""
            typeset weak=""

            for comm in $COMMUNITIES; do
                for weak in $WEAK_STRINGS; do
                    if [ "$comm" = "$weak" ]; then
                        HAS_WEAK="true"
                        break
                    fi
                done
            done

            if [ -z "$COMMUNITIES" ]; then
                RES="Y"
                DESC="Community String 미사용 (SNMPv3 사용)"
                DT="설정 파일: $CONF_FILE
    Community: 설정 없음"
            elif [ "$HAS_WEAK" = "true" ]; then
                RES="N"
                DESC="취약한 Community String 사용 중"
                DT="설정 파일: $CONF_FILE
    Community: $COMMUNITIES"
            else
                RES="Y"
                DESC="Community String이 복잡하게 설정됨"
                DT="설정 파일: $CONF_FILE
    Community: $COMMUNITIES"
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

        # AIX uses /etc/snmpdv3.conf
        typeset SNMP_CONF="/etc/snmpdv3.conf"
        typeset SNMP_CONF2="/etc/snmp/snmpd.conf"

        typeset CONF_FILE=""
        if [ -f "$SNMP_CONF" ]; then
            CONF_FILE="$SNMP_CONF"
        elif [ -f "$SNMP_CONF2" ]; then
            CONF_FILE="$SNMP_CONF2"
        fi

        if [ -z "$CONF_FILE" ]; then
            RES="N/A"
            DESC="SNMP 설정 파일이 없음"
            DT="snmpd 설정 파일: 없음"
        else
            typeset DETAILS=""
            typeset HAS_ISSUE="false"

            if [ "$CONF_FILE" = "$SNMP_CONF" ]; then
                # AIX snmpdv3.conf: COMMUNITY line contains network restriction
                # Format: COMMUNITY <name> <name> noAuthNoPriv <IP> <netmask> -
                typeset COMM_LINES=""
                COMM_LINES=$(grep -i "^COMMUNITY" "$CONF_FILE" 2>/dev/null | head -10)
                if [ -n "$COMM_LINES" ]; then
                    DETAILS="COMMUNITY 설정:
    $COMM_LINES"
                    # Check if network restriction is 0.0.0.0 (unrestricted)
                    typeset line=""
                    echo "$COMM_LINES" | while read line; do
                        typeset NET_ADDR=""
                        NET_ADDR=$(echo "$line" | awk '{print $5}')
                        if [ "$NET_ADDR" = "0.0.0.0" ]; then
                            HAS_ISSUE="true"
                        fi
                    done
                else
                    DETAILS="COMMUNITY 설정: 없음"
                fi
            else
                # net-snmp style
                typeset ACCESS_CONTROL=""
                ACCESS_CONTROL=$(grep -iE "^com2sec|^group|^access|^view" "$CONF_FILE" 2>/dev/null | head -10)
                if [ -n "$ACCESS_CONTROL" ]; then
                    DETAILS="접근 제어 설정:
    $ACCESS_CONTROL"
                fi

                typeset ROCOMM=""
                ROCOMM=$(grep -E "^rocommunity[[:space:]]" "$CONF_FILE" 2>/dev/null)
                typeset RWCOMM=""
                RWCOMM=$(grep -E "^rwcommunity[[:space:]]" "$CONF_FILE" 2>/dev/null)

                if [ -n "$ROCOMM" ] || [ -n "$RWCOMM" ]; then
                    DETAILS="${DETAILS}
    --- Community 설정 ---"
                    [ -n "$ROCOMM" ] && DETAILS="${DETAILS}
    $ROCOMM"
                    [ -n "$RWCOMM" ] && DETAILS="${DETAILS}
    $RWCOMM"

                    typeset ALL_COMMS=""
                    ALL_COMMS=$(printf "%s\n%s" "$ROCOMM" "$RWCOMM" | grep -v "^$")
                    echo "$ALL_COMMS" | while read line; do
                        typeset fields=""
                        fields=$(echo "$line" | awk '{print NF}')
                        if [ "$fields" -le 2 ]; then
                            HAS_ISSUE="true"
                        fi
                    done
                fi
            fi

            if [ "$HAS_ISSUE" = "true" ]; then
                RES="N"
                DESC="SNMP 접근 제어 네트워크 제한 미설정"
            elif [ -n "$DETAILS" ]; then
                RES="M"
                DESC="SNMP 접근 제어 수동 확인 필요"
            else
                RES="N"
                DESC="SNMP 접근 제어 미설정"
            fi
            DT="설정 파일: $CONF_FILE
    $DETAILS"
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

        typeset BANNER_FILES="/etc/motd /etc/issue /etc/issue.net"
        typeset HAS_BANNER="false"
        typeset DETAILS=""

        typeset file=""
        for file in $BANNER_FILES; do
            if [ -f "$file" ] && [ -s "$file" ]; then
                typeset CONTENT=""
                CONTENT=$(head -3 "$file" 2>/dev/null)
                DETAILS="${DETAILS}${file}:
    $CONTENT

    "
                HAS_BANNER="true"
            fi
        done

        # AIX Telnet 배너: /etc/security/login.cfg의 herald 설정
        if [ -f "$SECURITY_LOGIN" ]; then
            typeset HERALD=""
            HERALD=$(grep -i "herald" "$SECURITY_LOGIN" 2>/dev/null)
            if [ -n "$HERALD" ]; then
                DETAILS="${DETAILS}login.cfg herald: $HERALD
    "
                HAS_BANNER="true"
            fi
        fi

        # SSH 배너 확인
        if [ -f "$SSHD_CONFIG" ]; then
            typeset SSH_BANNER=""
            SSH_BANNER=$(grep -i "^Banner" "$SSHD_CONFIG" 2>/dev/null | awk '{print $2}')
            if [ -n "$SSH_BANNER" ] && [ "$SSH_BANNER" != "none" ]; then
                DETAILS="${DETAILS}SSH Banner: $SSH_BANNER"
                HAS_BANNER="true"
            fi
        fi

        if [ "$HAS_BANNER" = "true" ]; then
            RES="Y"
            DESC="로그인 경고 메시지가 설정됨"
        else
            RES="N"
            DESC="로그인 경고 메시지가 미설정"
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

            # 파일 권한 및 소유자 확인
            typeset OWNER=""
            OWNER=$(get_file_owner "$SUDOERS")
            typeset PERM=""
            PERM=$(get_file_perm "$SUDOERS")

            if [ "$OWNER" != "root" ]; then
                HAS_ISSUE="true"
                DETAILS="소유자: $OWNER (취약 - root 아님)"
            else
                DETAILS="소유자: $OWNER (양호)"
            fi

            if [ "$PERM" -gt 640 ] 2>/dev/null; then
                HAS_ISSUE="true"
                DETAILS="${DETAILS}
    권한: $PERM (취약 - 640 초과)"
            else
                DETAILS="${DETAILS}
    권한: $PERM (양호)"
            fi

            # NOPASSWD 또는 ALL 권한 확인
            typeset NOPASSWD=""
            NOPASSWD=$(grep -v "^#" "$SUDOERS" 2>/dev/null | grep "NOPASSWD")
            typeset ALL_ALL=""
            ALL_ALL=$(grep -v "^#" "$SUDOERS" 2>/dev/null | grep "ALL=(ALL)")

            typeset NP_STATUS="없음"
            if [ -n "$NOPASSWD" ]; then
                NP_STATUS="있음"
            fi
            typeset AA_STATUS="없음"
            if [ -n "$ALL_ALL" ]; then
                AA_STATUS="있음"
            fi

            DETAILS="${DETAILS}
    NOPASSWD 설정: $NP_STATUS
    ALL 권한: $AA_STATUS"

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

        # AIX OS 레벨 확인
        typeset OSLEVEL=""
        OSLEVEL=$(oslevel -s 2>/dev/null)
        if [ -n "$OSLEVEL" ]; then
            DETAILS="oslevel -s: $OSLEVEL"
        else
            typeset OSLEVEL_R=""
            OSLEVEL_R=$(oslevel -r 2>/dev/null)
            DETAILS="oslevel -r: ${OSLEVEL_R:-확인불가}"
        fi

        # 패치 리스트 확인
        typeset ML_INFO=""
        ML_INFO=$(instfix -i 2>/dev/null | grep ML | tail -5)
        if [ -n "$ML_INFO" ]; then
            DETAILS="${DETAILS}
    ML 패치 정보:
    $ML_INFO"
        fi

        typeset SP_INFO=""
        SP_INFO=$(instfix -i 2>/dev/null | grep SP | tail -5)
        if [ -n "$SP_INFO" ]; then
            DETAILS="${DETAILS}
    SP 패치 정보:
    $SP_INFO"
        fi

        RES="M"
        DESC="보안 패치 적용 여부 수동 확인 필요"
        DT="$DETAILS"

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

        typeset RUNNING="false"
        typeset DETAILS=""

        # AIX uses xntpd daemon
        if is_service_active "xntpd"; then
            RUNNING="true"
            DETAILS="lssrc -s xntpd: active"
        fi

        # xntpd 프로세스 확인
        if is_process_running "xntpd"; then
            RUNNING="true"
            DETAILS="${DETAILS}
    xntpd 프로세스: 실행 중"
        fi

        # ntpd도 확인
        if is_process_running "ntpd"; then
            RUNNING="true"
            DETAILS="${DETAILS}
    ntpd 프로세스: 실행 중"
        fi

        # NTP 설정 파일 확인
        typeset NTP_CONF="/etc/ntp.conf"
        if [ -f "$NTP_CONF" ]; then
            typeset NTP_SERVERS=""
            NTP_SERVERS=$(grep -i "^server" "$NTP_CONF" 2>/dev/null)
            if [ -n "$NTP_SERVERS" ]; then
                DETAILS="${DETAILS}
    $NTP_CONF:
    $NTP_SERVERS"
            else
                DETAILS="${DETAILS}
    $NTP_CONF: server 설정 없음"
            fi
        else
            DETAILS="${DETAILS}
    $NTP_CONF: 없음"
        fi

        # ntpq로 동기화 상태 확인
        typeset NTP_PEERS=""
        NTP_PEERS=$(ntpq -pn 2>/dev/null | head -5)
        if [ -n "$NTP_PEERS" ]; then
            DETAILS="${DETAILS}
    ntpq -pn:
    $NTP_PEERS"
        fi

        if [ "$RUNNING" = "true" ]; then
            RES="Y"
            DESC="시각 동기화가 설정됨"
        else
            RES="N"
            DESC="시각 동기화가 미설정"
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

        # AIX uses /etc/syslog.conf (not rsyslog)
        typeset SYSLOG_CONF="/etc/syslog.conf"
        typeset DETAILS=""
        typeset AUTHLOG=""

        if [ -f "$SYSLOG_CONF" ]; then
            # 주요 로그 설정 확인
            AUTHLOG=$(grep -E "auth\." "$SYSLOG_CONF" 2>/dev/null | grep -v "^#" | head -3)
            typeset MESSAGES=""
            MESSAGES=$(grep -E "^\*\." "$SYSLOG_CONF" 2>/dev/null | grep -v "^#" | head -5)
            typeset EMERG=""
            EMERG=$(grep -E "emerg|alert" "$SYSLOG_CONF" 2>/dev/null | grep -v "^#" | head -3)

            DETAILS="$SYSLOG_CONF 설정:
    ${AUTHLOG:-auth 설정 없음}
    ${MESSAGES:-전체(*) 설정 없음}
    ${EMERG:-emerg/alert 설정 없음}"
        else
            DETAILS="$SYSLOG_CONF: 없음"
        fi

        # syslogd 서비스 상태 확인
        typeset SYSLOGD_ACTIVE="false"
        if is_service_active "syslogd"; then
            SYSLOGD_ACTIVE="true"
            DETAILS="${DETAILS}
    syslogd: active"
        fi

        if [ -n "$AUTHLOG" ]; then
            RES="Y"
            DESC="시스템 로깅이 설정됨"
        elif [ "$SYSLOGD_ACTIVE" = "true" ]; then
            RES="M"
            DESC="syslogd 실행 중, 설정 수동 확인 필요"
        else
            RES="N"
            DESC="syslogd 서비스가 실행되지 않음"
            DETAILS="${DETAILS}
    syslogd: 미실행"
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

        # AIX logs are in /var/adm/
        typeset LOG_DIR="/var/adm"
        typeset VULNERABLE=""
        typeset DETAILS=""

        # /var/adm 디렉토리 권한 확인
        typeset DIR_PERM=""
        DIR_PERM=$(get_file_perm "$LOG_DIR")
        typeset DIR_OWNER=""
        DIR_OWNER=$(get_file_owner "$LOG_DIR")
        DETAILS="$LOG_DIR: ${DIR_OWNER}:${DIR_PERM}"

        # 주요 로그 파일 권한 확인
        typeset LOG_FILES="messages syslog wtmp sulog auth.log error.log mail.log"
        typeset log=""
        for log in $LOG_FILES; do
            typeset LOG_PATH="$LOG_DIR/$log"
            if [ -f "$LOG_PATH" ]; then
                typeset perm=""
                perm=$(get_file_perm "$LOG_PATH")
                typeset owner=""
                owner=$(get_file_owner "$LOG_PATH")
                DETAILS="${DETAILS}
    ${log}: ${owner}:${perm}"
                # 소유자가 root가 아니거나 권한이 644 초과 시 취약
                if [ "$owner" != "root" ] || [ "$perm" -gt 644 ] 2>/dev/null; then
                    VULNERABLE="${VULNERABLE}${log} "
                fi
            fi
        done

        if [ -z "$VULNERABLE" ]; then
            RES="Y"
            DESC="로그 파일 권한이 적절히 설정됨"
        else
            RES="N"
            DESC="로그 파일 권한이 부적절함"
        fi

        DT="${DETAILS}
    취약: ${VULNERABLE:-없음}"

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
