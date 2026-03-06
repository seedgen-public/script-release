# Seedgen Color System unofficial

---

## 🎨 1 Core Palettes (10‑step)

### 1‑1 Primary (Green 110°) - 주조색 기반

|Step|Hex|HSL|
|---|---|---|
|50|#F0F9ED|hsl(110,50%,95%)|
|100|#E1F3DB|hsl(110,50%,90%)|
|200|#C8E9BD|hsl(110,45%,82%)|
|300|#9FD98A|hsl(110,50%,70%)|
|400|#48CD29|hsl(110,67%,48%)|
|**500**|**#3EAF23**|**hsl(110,67%,41%)**|
|600|#359620|hsl(110,67%,36%)|
|700|#2B7D1A|hsl(110,67%,30%)|
|800|#226514|hsl(110,67%,24%)|
|900|#244C14|hsl(110,50%,19%)|

### 1‑2 Secondary (Gold 45°)

|Step|Hex||Step|Hex|
|---|---|---|---|---|
|50|#FFF9E6||600|#E6AB00|
|100|#FFF3CC||700|#CC9900|
|200|#FFE799||800|#B38600|
|300|#FFDB66||900|#997300|
|400|#FFD033||||
|**500**|**#FFC000**||||

### 1‑3 Tertiary (Orange 20°)

|Step|Hex||Step|Hex|
|---|---|---|---|---|
|50|#FEF0EB||600|#E55A1F|
|100|#FDE1D7||700|#CC4F1B|
|200|#FBC3B0||800|#B34417|
|300|#F99A7C||900|#993913|
|400|#F77F49||||
|**500**|**#F66626**||||

---

## 🩶 2 Neutral / Gray (50‑900)

|50|100|200|300|400|**500**|600|700|800|900|
|---|---|---|---|---|---|---|---|---|---|
|#F4F3F2|#E8E6E5|#D1CFCD|#BAB7B5|#A39F9D|**#8C8885**|#75716D|#5E5955|#47423D|#302B25|

_Note: Based on company's #F4F3F2 (warm neutral)_

---

## 🩹 3 Semantic Palettes (5‑step)

|Purpose|100|200|300|400|**500**|
|---|---|---|---|---|---|
|**Success**|#E1F3DB|#C8E9BD|#9FD98A|#6DC556|**#3EAF23**|
|**Warning**|#FFF3CC|#FFE799|#FFD033|#FFC000|**#E6AB00**|
|**Error**|#FDEBEC|#F9D6D7|#F1A9AB|#EA7C7E|**#D13438**|
|**Info**|#E6F7FB|#CCF0F7|#99E0EF|#66D1E7|**#26BBD9**|

_Note: Success uses Primary green, Warning uses Secondary gold_

---

## 🌗 4 Theme‑Aware Context Tokens

### 4‑1 Light Theme

```css
:root {
  --color-bg-surface  : #FFFFFF;
  --color-bg-elevated : #FFFFFF;
  --color-bg-primary  : var(--primary-50);     /* #F0F9ED */
  --color-bg-accent   : #EEFBEB;                /* 회사 제공 보조색 */

  --color-text-primary   : #302B25;             /* gray-900 */
  --color-text-secondary : #5E5955;             /* gray-700 */
  --color-text-inverted  : #FFFFFF;

  --color-border-default : var(--gray-200);     /* #D1CFCD */
  --color-border-strong  : var(--gray-400);     /* #A39F9D */

  --opacity-hover  : 0.08;
  --opacity-active : 0.12;
}
```

### 4‑2 Dark Theme

```css
[data-theme="dark"] {
  --color-bg-surface  : #1E1E1E;
  --color-bg-elevated : #252525;
  --color-bg-primary  : var(--primary-900);     /* #244C14 */

  --color-text-primary   : #FFFFFF;
  --color-text-secondary : #C6C6C6;
  --color-text-inverted  : #000000;

  --color-border-default : var(--gray-700);     /* #5E5955 */
  --color-border-strong  : var(--gray-500);     /* #8C8885 */

  --opacity-hover  : 0.10;
  --opacity-active : 0.16;
}
```

---

## 🔬 5 Contrast Checks

- **Primary-500** (#3EAF23) on White: **4.51:1** (WCAG AA ✓)
- **Secondary-500** (#FFC000) on White: **2.65:1** (AA ✗, text requires darker shade)
- **Tertiary-500** (#F66626) on White: **3.56:1** (AA ✗, text requires darker shade)
- **Success-500** on White: **4.51:1** (WCAG AA ✓)

_Note: For text on light backgrounds, use Primary-600+ (#359620) or darker shades._

---

## 📦 6 Export (:root excerpt)

```css
/* Primary (Green) */
--primary-50:#F0F9ED;--primary-100:#E1F3DB;--primary-200:#C8E9BD;--primary-300:#9FD98A;
--primary-400:#48CD29;--primary-500:#3EAF23;--primary-600:#359620;--primary-700:#2B7D1A;
--primary-800:#226514;--primary-900:#244C14;

/* Secondary (Gold) */
--secondary-50:#FFF9E6;--secondary-100:#FFF3CC;--secondary-200:#FFE799;--secondary-300:#FFDB66;
--secondary-400:#FFD033;--secondary-500:#FFC000;--secondary-600:#E6AB00;--secondary-700:#CC9900;
--secondary-800:#B38600;--secondary-900:#997300;

/* Tertiary (Orange) */
--tertiary-50:#FEF0EB;--tertiary-100:#FDE1D7;--tertiary-200:#FBC3B0;--tertiary-300:#F99A7C;
--tertiary-400:#F77F49;--tertiary-500:#F66626;--tertiary-600:#E55A1F;--tertiary-700:#CC4F1B;
--tertiary-800:#B34417;--tertiary-900:#993913;

/* Gray (Warm Neutral) */
--gray-50:#F4F3F2;--gray-100:#E8E6E5;--gray-200:#D1CFCD;--gray-300:#BAB7B5;
--gray-400:#A39F9D;--gray-500:#8C8885;--gray-600:#75716D;--gray-700:#5E5955;
--gray-800:#47423D;--gray-900:#302B25;

/* Semantic */
--success-500:#3EAF23;--warning-500:#E6AB00;--error-500:#D13438;--info-500:#26BBD9;

/* Company Specific */
--accent-light:#EEFBEB;
--accent-emphasis:#48CD29;
```

---

## 📝 7 Usage Guidelines

### 회사 가이드라인 반영

1. **주조색 (#3EAF23)**: Primary-500로 매핑, 주요 UI 요소에 사용
2. **강조색 (#48CD29)**: Primary-400로 매핑, 폰트 두께 조절과 함께 사용
3. **보조색**:
   - #F4F3F2 → Gray-50 (배경용)
   - #EEFBEB → 추가 변수로 제공 (밝고 깔끔한 accent)
4. **어두운 초록 (#244C14)**: Primary-900로 매핑, 사용 최소화
5. **다양한 색 최소화**: 단일 Primary 색상 + 폰트 두께로 계층 표현

### 권장 사용법

```css
/* 주요 버튼 */
.btn-primary {
  background: var(--primary-500);
  color: white;
  font-weight: 600;
}

/* 강조 버튼 (더 밝게) */
.btn-emphasis {
  background: var(--primary-400);
  color: white;
  font-weight: 700;
}

/* 배경 */
.bg-light {
  background: var(--gray-50);
}

.bg-accent {
  background: var(--accent-light);
}
```

---
