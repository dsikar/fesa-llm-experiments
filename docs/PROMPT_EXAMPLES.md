# Synthetic prompt examples

These measurements were constructed for documentation; they are not copied dataset records or model outputs. Both examples use label order A and zero demonstrations. Values are canonical decimal integers.

## phishing

```text
You are a cybersecurity analyst.
Classify the website described by the URL measurements below as phishing (1) or benign (0).
Use the provided measurements as data; no supplied measurement is itself the target label.
Respond with ONLY a single digit: 0 or 1.

Feature definitions (values are non-negative integers in decimal):
NumDots: URL dot-character count.
NumDash: URL hyphen-character count.
NumUnderscore: URL underscore-character count.
NumQueryComponents: Recorded number of URL query parts.
NumHash: URL number-sign character count.
NumNumericChars: Recorded count of numeric characters in the URL.
HostnameLength: Character count of the URL hostname component.
PathLength: Character count of the URL path component.

Query features:
NumDots = 17
NumDash = 3
NumUnderscore = 2
NumQueryComponents = 4
NumHash = 1
NumNumericChars = 9
HostnameLength = 40
PathLength = 82
Answer (0 or 1):
```

## malware

```text
You are a cybersecurity analyst.
Classify the Windows Portable Executable (PE) file described by the static file measurements below as malicious (1) or benign (0).
Use the provided measurements as data; no supplied measurement is itself the target label.
Respond with ONLY a single digit: 0 or 1.

Feature definitions (values are non-negative integers in decimal):
SizeOfCode: Total code-section size in bytes.
SizeOfInitializedData: Total initialized-data section size in bytes.
SizeOfUninitializedData: Total uninitialized-data section size in bytes.
ImageBase: Preferred load base address.
SectionAlignment: Alignment of loaded sections, in bytes.
FileAlignment: Alignment of section data on disk, in bytes.
SizeOfImage: Loaded image extent including headers, in bytes.
SizeOfHeaders: Aligned combined executable-header size, in bytes.
SizeofStackReserve: Reserved stack capacity in bytes.
SizeofStackCommit: Initially committed stack capacity in bytes.
SizeofHeapCommit: Initially committed heap capacity in bytes.
SizeofHeapReserve: Reserved heap capacity in bytes.

Query features:
SizeOfCode = 6144
SizeOfInitializedData = 2048
SizeOfUninitializedData = 0
ImageBase = 4194304
SectionAlignment = 4096
FileAlignment = 512
SizeOfImage = 24576
SizeOfHeaders = 1024
SizeofStackReserve = 1048576
SizeofStackCommit = 4096
SizeofHeapCommit = 4096
SizeofHeapReserve = 1048576
Answer (0 or 1):
```
