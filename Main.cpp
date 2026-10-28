// ---------------------------------------------------------------------------------------------------------------------------------------------------------------------------
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <tchar.h>
#include <windows.h>

#define _CRT_SECURE_NO_WARNINGS

// ---------------------------------------------------------------------------------------------------------------------------------------------------------------------------
int _tmain (int argc, TCHAR *argv[])
{
	FILE *pFile;
	struct _IMAGE_DOS_HEADER udtDOSHeader;
	struct _IMAGE_NT_HEADERS udtPEHeader;

	_tprintf(_T("\nPatchPE 1.36 - (c) 2017-2025 by Javier Gutierrez Chamorro\n"));
	_tprintf(_T("Patches PE executable headers to make them compatible with older versions of Windows\n\n"));
	
	if (argc < 2)
	{
		_tprintf(_T("Usage: patchpe.exe <File>\n"));
		_tprintf(_T("Example: patchpe.exe notepad.exe\n"));
		return(-1);
	}

	pFile = _tfopen(argv[1], _T("r+b"));
	if (!pFile)
	{
		_tprintf(_T("Cannot read input file %s\n"), argv[1]);
		return(-2);
	}

	//Read DOS header
	if (fread(&udtDOSHeader, 1, sizeof(udtDOSHeader), pFile) != sizeof(udtDOSHeader))
	{
		fclose(pFile);
		_tprintf(_T("Cannot read DOS header %s\n"), argv[1]);
		return(-3);
	}
	if ((udtDOSHeader.e_magic != (WORD) 'MZ') && (udtDOSHeader.e_magic != (WORD) 'ZM'))
	{
		fclose(pFile);
		_tprintf(_T("Not a valid DOS Executable %s\n"), argv[1]);
		return(-4);
	}

	//Read PE Header
	if (fseek(pFile, udtDOSHeader.e_lfanew, SEEK_SET) != 0)
	{
		fclose(pFile);
		_tprintf(_T("Cannot seek to read PE header %s\n"), argv[1]);
		return(-5);
	}
	if (fread(&udtPEHeader, 1, sizeof(udtPEHeader), pFile) != sizeof(udtPEHeader))
	{
		fclose(pFile);
		_tprintf(_T("Cannot read PE header %s\n"), argv[1]);
		return(-6);
	}
	//if (udtPEHeader.Signature != 'EP')
	if (udtPEHeader.Signature != IMAGE_NT_SIGNATURE)
	{
		fclose(pFile);
		_tprintf(_T("Not a valid PE Executable. Invalid PE header %s\n"), argv[1]);
		return(-7);
	}

	//Check PE Optional header
	if ((udtPEHeader.OptionalHeader.Magic != IMAGE_NT_OPTIONAL_HDR32_MAGIC) && (udtPEHeader.OptionalHeader.Magic != IMAGE_NT_OPTIONAL_HDR64_MAGIC))
	{
		fclose(pFile);
		_tprintf(_T("Not a valid PE Executable. Invalid optional PE header %s\n"), argv[1]);
		return(-8);
	}
	_tprintf(_T("File: %s\n"), argv[1]);
	_tprintf(_T("Operating System Version: %u.%02u\n"), udtPEHeader.OptionalHeader.MajorOperatingSystemVersion, udtPEHeader.OptionalHeader.MinorOperatingSystemVersion);
	_tprintf(_T("Image Version: %u.%02u\n"), udtPEHeader.OptionalHeader.MajorImageVersion, udtPEHeader.OptionalHeader.MinorImageVersion);
	_tprintf(_T("Subsystem Version: %u.%02u\n"), udtPEHeader.OptionalHeader.MajorSubsystemVersion, udtPEHeader.OptionalHeader.MinorSubsystemVersion);
	_tprintf(_T("Large Address Aware: "));
	if (udtPEHeader.FileHeader.Characteristics & IMAGE_FILE_LARGE_ADDRESS_AWARE)
	{
		_tprintf(_T("Yes (>3GB)\n"));
	}
	else
	{
		_tprintf(_T("No (2GB)\n"));
	}
	_tprintf(_T("Aggressively trim the working set: "));
	if (udtPEHeader.FileHeader.Characteristics & IMAGE_FILE_AGGRESIVE_WS_TRIM)
	{
		_tprintf(_T("Yes\n"));
	}
	else
	{
		_tprintf(_T("No\n"));
	}
	//Patch header
	udtPEHeader.OptionalHeader.MajorOperatingSystemVersion = 4;
	udtPEHeader.OptionalHeader.MinorOperatingSystemVersion = 0;
	udtPEHeader.OptionalHeader.MajorSubsystemVersion = 4;
	udtPEHeader.OptionalHeader.MinorSubsystemVersion = 0;
	udtPEHeader.FileHeader.Characteristics |= (IMAGE_FILE_LARGE_ADDRESS_AWARE | IMAGE_FILE_AGGRESIVE_WS_TRIM);

	//Write PE header
	if (fseek(pFile, udtDOSHeader.e_lfanew, SEEK_SET) != 0)
	{
		fclose(pFile);
		_tprintf(_T("Cannot seek to write new PE header %s\n"), argv[1]);
		return(-9);
	}
	if (fwrite(&udtPEHeader, 1, sizeof(udtPEHeader), pFile) != sizeof(udtPEHeader))
	{
		fclose(pFile);
		_tprintf(_T("Cannot write new header %s\n"), argv[1]);
		return(-10);
	}
	
	_tprintf(_T("\nPatched successfully!\n\n"));

	fclose(pFile);
	
	return(0);
}