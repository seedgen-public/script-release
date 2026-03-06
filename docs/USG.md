# Universal Script Guide

> 보안 진단 스크립트 공통 정책

---

## 1. 개요

본 문서는 Seedgen 보안 진단 스크립트의 **최상위 공통 정책**을 정의한다.
모든 플랫폼(OS, DB, WAS 등)의 스크립트는 이 정책을 기반으로 작성한다.

---

## 2. 문서 구조

### 2.1 가이드 문서

| 문서 | 설명 | 대상 |
|------|------|------|
| [XML-Spec](./XML-Spec.md) | XML 출력 스펙 정의 | 파서 개발자 |
| [Scripting](./Scripting.md) | 스크립트 개발 가이드 | 스크립트 개발자 |
| [Standards](./Standards.md) | 코드 체계 및 표준 | 전체 |
| [Workflow](./Workflow.md) | 변경이력/이슈 처리 | 운영자 |
| [Logic](./Logic.md) | 진단 로직 작성 가이드 | 스크립트 개발자 |
| [Recipe](./Recipe.md) | Recipe 정리 가이드 | 스크립트 개발자 |

### 2.2 플랫폼별 가이드

| 플랫폼 | 문서 | 코드 접두사 |
|--------|------|-------------|
| Linux/Unix | [Linux](./OS/Linux.md) | U-XX |
| Windows | [Windows](./OS/Windows.md) | W-XX |

### 2.3 폴더 구조

```
(repo root)
├── docs/                   ← 문서
│   ├── USG.md              ← 인덱스 (현재 문서)
│   ├── XML-Spec.md
│   ├── Scripting.md
│   ├── Standards.md
│   ├── Workflow.md
│   ├── Logic.md
│   ├── Recipe.md
│   └── OS/
│       ├── Linux.md
│       └── Windows.md
├── scripts/                ← 스크립트
│   ├── 1. OS/
│   ├── 2. DBMS/
│   ├── 3. WEBWAS/
│   └── 4. PC/
├── history/                ← 변경이력
└── README.md
```

---

## 3. 빠른 참조

### 결과값 상수

| 값 | 의미 |
|----|------|
| `Y` | 양호 |
| `N` | 취약 |
| `N/A` | 해당없음 |
| `M` | 수동확인 |

### 진단 코드 접두사

| 플랫폼 | 접두사 | 플랫폼 | 접두사 |
|--------|--------|--------|--------|
| Linux/Unix | `U-` | Windows | `W-` |
| MySQL | `M-` | MSSQL | `S-` |
| Oracle | `O-` | Apache | `A-` |
| Nginx | `N-` | Tomcat | `T-` |
| IIS | `I-` | PC | `PC-` |

### 버전 넘버링

```
YYMMDDHH[e]
```
- `26010914` - 2026년 1월 9일 14시
- `26011516e` - 이슈 수정 버전 (e = edit)

---

*v3.1 | 2026-02-01 | Seedgen*

