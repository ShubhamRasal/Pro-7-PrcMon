#include<iostream>
#include<windows.h>
#include<tlhelp32.h>
#include<stdio.h>
#include<io.h>
#include<string.h>
#include<sys/types.h>
#include<sys/stat.h>
#include<winbase.h>
#define _CRT_SECURE_NO_DEPRECATE
#define _CRT_SECURE_NO_WARNINGS
using namespace std;

typedef struct LogFile
{
	char ProcessName[100];
	unsigned int pid; //process Id
	unsigned int ppid;// parent process Id
	unsigned int thread_cnt; // count of Thread
}LOGFILE;

class ThreadInfo
{
private:
	DWORD PID;
	HANDLE hThreadSnap;
	THREADENTRY32 te32;

public:
	ThreadInfo(DWORD);
	BOOL ThreadDisplay();
};

ThreadInfo::ThreadInfo(DWORD no)
{
	PID = no;
	hThreadSnap = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, PID);

	if (hThreadSnap == INVALID_HANDLE_VALUE)
	{
		cout << "Unable to create the snapshot of current thread pool" << endl;
		return;
	}

	te32.dwSize = sizeof(THREADENTRY32);
}

BOOL ThreadInfo::ThreadDisplay()
{
	if (!Thread32First(hThreadSnap, &te32))
	{
		cout << "Error : Getting the First Thread" << endl;
		CloseHandle(hThreadSnap);
		return FALSE;
	}

	cout << endl << "Thread of this Process:" << endl;

	do
	{
		if (te32.th32OwnerProcessID == PID)
		{
			cout << "\tTHREAD ID" << te32.th32ThreadID << endl;
		}
	} while (Thread32Next(hThreadSnap, &te32));

	CloseHandle(hThreadSnap);

	return TRUE;

}


class DLLInfo
{
private:
	DWORD PID;
	HANDLE hProcessSnap;
	MODULEENTRY32 me32;

public:
	DLLInfo(DWORD);
	BOOL DependentDLLDisplay();
};

DLLInfo::DLLInfo(DWORD no)
{
	PID = no;
	hProcessSnap = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE, PID);

	if (hProcessSnap == INVALID_HANDLE_VALUE)
	{
		cout << "Unable to create the snapshot of current thread pool" << endl;
		return;
	}

	me32.dwSize = sizeof(MODULEENTRY32);


}

BOOL DLLInfo::DependentDLLDisplay()
{
	char arr[200];

	if (!Module32First(hProcessSnap, &me32))
	{
		cout << "FAILED to get DLL information" << endl;

		CloseHandle(hProcessSnap);
		return FALSE;
	}

	cout << "Dependent DLL of this process" << endl;

	do
	{
		//wcstombs_s(NULL, arr, 200, me32.szModule, 200);
		//cout << arr << endl;
		cout << me32.szModule << endl;
	} while (Module32Next(hProcessSnap, &me32));

	CloseHandle(hProcessSnap);

	return TRUE;
}


class ProcessInfo
{
private:
	DWORD PID;
	DLLInfo * pdobj;
	ThreadInfo * ptobj;
	HANDLE hProcessSnap;
	PROCESSENTRY32 pe32;

public:
	ProcessInfo();
	BOOL ProcessDisplay(const char *);
	BOOL ProcessLog();
	BOOL ReadLog(DWORD, DWORD, DWORD, DWORD);
	BOOL ProcessSearch(char *);
	BOOL KillProcess(char *);
};

ProcessInfo::ProcessInfo()
{
	ptobj = NULL;
	pdobj = NULL;

	hProcessSnap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);

	if (hProcessSnap == INVALID_HANDLE_VALUE)
	{
		cout << "Unable to create the Snapshot of running Processes" << endl;
		return;
	}

	pe32.dwSize = sizeof(PROCESSENTRY32);

}

BOOL ProcessInfo::ProcessLog()
{
	const char* month[] = { "JAN","FEB","MAR","APR","MAY","JUN","JUL","AUG","SEP","OCT","NOV","DEC" };
	char FileName[50], arr[512];
	int ret = 0, fd = 0, count = 0;
	SYSTEMTIME lt;
	LOGFILE fobj;
	FILE *fp;
	//SetCurrentDirectory("C://");
	//_chdir("C://");

	GetLocalTime(&lt); // get system time(current)
			//buffer	formaterd String                           parameters				
	sprintf_s(FileName, "E://MarvellousLog %02d_%02d_%02d %s.txt", lt.wHour, lt.wMinute, lt.wDay, month[lt.wMonth - 1]);

	fp = fopen(FileName, "wb"); // write binary(wb)
	if (fp == NULL)
	{
		cout << "Unable to create log file" << endl;
		return FALSE;
	}
	else
	{
		cout << "Log file successfully gets created as : " << FileName << endl;
		cout << "Time of log file creation is->" << lt.wHour << ":" << lt.wMinute << ":" << lt.wDay << "th" << month[lt.wMonth - 1] << endl;
	}

	if (!Process32First(hProcessSnap, &pe32))
	{
		cout << "ERROR : In finding the first process." << endl;
		CloseHandle(hProcessSnap);
		return FALSE;

	}
	do
	{
		//wcstombs_s(NULL, arr, 200, pe32.szExeFile, 200);
		//strcpy_s(fobj.ProcessName, arr);
		strcpy_s(fobj.ProcessName, pe32.szExeFile);
		fobj.pid = pe32.th32ProcessID;
		fobj.ppid = pe32.th32ParentProcessID;
		fobj.thread_cnt = pe32.cntThreads;
		fwrite(&fobj, sizeof(fobj), 1, fp);
		// address of object size of obj , no of times , file Discripter
	} while (Process32Next(hProcessSnap, &pe32));

	CloseHandle(hProcessSnap);
	fclose(fp);
	return TRUE;

}

BOOL ProcessInfo::ProcessDisplay(const char * option)
{
	char arr[200];

	// Retrieve information about the first process,
	// and exit if unsucc000essful
	if (!Process32First(hProcessSnap, &pe32))
	{
		cout << "ERROR:In finding the First process" << endl;
		CloseHandle(hProcessSnap);          // clean the snapshot object
		return(FALSE);
	}

	// Now walk the snapshot of processes, and
	// display information about each process in turn
	do
	{
		//wcstombs_s(NULL, arr, 200, (const wchar_t *)pe32.szExeFile, 200);
		// Retrieve the priority class.
		cout << endl << "PROCESS NAME:" << pe32.szExeFile;
		cout << endl << "PID:" << pe32.th32ProcessID;
		cout << endl << "Parent ID:" << pe32.th32ParentProcessID;
		cout << endl << "NO of Threads:" << pe32.cntThreads;

		if ((_stricmp(option, "-a") == 0) || (_stricmp(option, "-d") == 0) || (_stricmp(option, "-t") == 0))
		{
			if ((_stricmp(option, "-a") == 0) || (_stricmp(option, "-t") == 0))
			{
				ptobj = new ThreadInfo(pe32.th32ProcessID);
				ptobj->ThreadDisplay();
				delete ptobj;

			}
			if ((_stricmp(option, "-a") == 0) || (_stricmp(option, "-d") == 0))
			{
				pdobj = new DLLInfo(pe32.th32ProcessID);
				pdobj->DependentDLLDisplay();
				delete pdobj;
			}
		}
		cout << "--------------------------------------" << endl;
	} while (Process32Next(hProcessSnap, &pe32));

	CloseHandle(hProcessSnap);
	return(TRUE);

}

BOOL ProcessInfo::ReadLog(DWORD hr, DWORD min, DWORD date, DWORD month)
{

	char FileName[50];
	const char* montharr[] = { "JAN","FEB","MAR","APR","MAY","JUN","JUL","AUG","SEP","OCT","NOV","DEC" };
	int ret = 0, count = 0;
	LOGFILE fobj;

	FILE *fp;

	sprintf_s(FileName, "E://MarvellousLog %02d_%02d_%02d %s.txt", hr, min, date, montharr[month - 1]);

	fp = fopen(FileName, "rb"); // read binary
	if (fp == NULL)
	{
		cout << "ERROR : Unable to open log File named as : " << FileName << endl;
		return FALSE;
	}

	while (ret = (fread(&fobj, 1, sizeof(fobj), fp)) != 0)
	{
		cout << "------------------------------------------------" << endl;
		cout << "Process Name : " << fobj.ProcessName << endl;
		cout << "PID of Current Process :" << fobj.pid << endl;
		cout << "Parent Process PID :" << fobj.ppid << endl;
		cout << "Thread Count of Process : " << fobj.thread_cnt << endl;
	}

	return TRUE;
}


BOOL ProcessInfo::ProcessSearch(char * name)
{
	char arr[200];

	BOOL flag = FALSE;

	if (!Process32First(hProcessSnap, &pe32))
	{
		CloseHandle(hProcessSnap);
		return FALSE;
	}

	do
	{
		//wcstombs_s(NULL, arr, 200, pe32.szExeFile, 200);
//		if (_stricmp(arr, name) == 0)

		if (_stricmp(pe32.szExeFile, name) == 0)
		{
			//cout << endl << "Process Name : " << arr;
			cout << endl << "Process Name : " << pe32.szExeFile;
			cout << endl << "PID : " << pe32.th32ProcessID;
			cout << endl << "Parent PID : " << pe32.th32ParentProcessID;
			cout << endl << "No. of Thread :" << pe32.cntThreads;

			flag = TRUE;

			break;
		}
	} while (Process32Next(hProcessSnap, &pe32));

	CloseHandle(hProcessSnap);

	return flag;
}

BOOL ProcessInfo::KillProcess(char * name)
{

	char arr[200];
	int pid = -1;

	BOOL bret;

	HANDLE hProcess;

	if (!Process32First(hProcessSnap, &pe32))
	{
		CloseHandle(hProcessSnap);
		return FALSE;
	}


	do
	{
	//wcstombs_s(NULL, arr, 200, pe32.szExeFile, 200);
//		if (_stricmp(arr, name) == 0)

		if (_stricmp(pe32.szExeFile, name) == 0)
		{
			pid = pe32.th32ProcessID;
			break;
		}

	} while (Process32Next(hProcessSnap, &pe32));

	CloseHandle(hProcessSnap);

	if (pid == -1)
	{
		cout << "ERROR : There is no such Process" << endl;
		return FALSE;
	}

	hProcess = OpenProcess(PROCESS_TERMINATE, FALSE, pid); // open process struct
	
	if (hProcess == NULL)
	{
		cout << "ERROR : There is no acess to Terminate" << endl;
		return FALSE;
	}

	bret = TerminateProcess(hProcess, 0);

	if (bret == FALSE)
	{
		cout << "ERROR : Unable to terminate the Process" << endl;
		return FALSE;
	}
}


BOOL HardwareInfo()
{
	SYSTEM_INFO siSysInfo;
	DWORD dwOemID;

	GetSystemInfo(&siSysInfo);

	cout<<"OEM ID : "<<siSysInfo.dwOemId<<endl;
	cout << "Number of Processors  : " << siSysInfo.dwNumberOfProcessors << endl;
	cout << "Page Size : " << siSysInfo.dwPageSize << endl;
	cout << "Processor Type : " << siSysInfo.dwProcessorType << endl;
	cout << "Minimum Application address : " << siSysInfo.lpMinimumApplicationAddress << endl;
	cout << "Maximum Application Address :" << siSysInfo.lpMaximumApplicationAddress << endl;
	cout << "Active Process mask : " << siSysInfo.dwActiveProcessorMask << endl;

	return TRUE;
}


void DisplayHelp()
{
	cout << "Developed by Marvallous Infosystem" << endl;
	cout << "ps : Display all information of process" << endl;
	cout << "ps -t : Dilsplay All information about Threads" << endl;
	cout << "ps -d : Display all information about DLL" << endl;
	cout << "cls : to Clear the console" << endl;
	cout << "log : Create Log of Current running Process on C drive" << endl;
	cout << "readlog : Display the information From specified log File" << endl;
	cout << "sysinfo : Display the Current Hardware configuration" << endl;
	cout << "search : Search and Display information of Specific running Process" << endl;
	cout << "kill : Terminate the Specific Process" << endl;
	cout << "exit : Terminate the ProcMon" << endl;


}

int main(int argc, char * argv[])
{
	BOOL bret = FALSE;
	char * ptr = NULL;
	ProcessInfo * ppobj = NULL;
	char command[4][80];
	char str[80];
	int count, min, date, month, hr;

	while (1)
	{
		fflush(stdin);
		strcpy(str, "");

		cout << endl << "Marvallous ProcMon : >";
		fgets(str, 80, stdin);

		count = sscanf(str, "%s %s %s %s ", command[0], command[1], command[2], command[3]);

		if (count == 1)
		{
			if (_stricmp(command[0], "ps") == 0)
			{
				ppobj = new ProcessInfo();
				bret = ppobj->ProcessDisplay("-a");

				if (bret == FALSE)
				{
					cout << "ERROR : Unable to Display Process" << endl;
				}
				delete ppobj;
			}
			else if (_stricmp(command[0], "log") == 0)
			{
				ppobj = new ProcessInfo();
				bret = ppobj->ProcessLog();

				if (bret == FALSE)
				{
					cout << "ERROR : Unable to create log File" << endl;
				}
				delete ppobj;
			}
			else if (_stricmp(command[0], "sysinfo") == 0)
			{
				bret = HardwareInfo();

				if (bret == FALSE)
				{
					cout << "ERROR : Unable to get HArdware Information" << endl;
				}
				cout << "Hardware information of current system is" << endl;
			}
			else if (_stricmp(command[0], "readlog") == 0)
			{
				ProcessInfo * ppobj;
				ppobj = new ProcessInfo();

				cout << "Enter log File details as : " << endl;

				cout << "Hour : ";
				cin >> hr;
				cout << endl << "Minute : ";
				cin >> min;
				cout << endl << "Date : ";
				cin >> date;;
				cout << endl << "Month : ";
				cin >> month;

				bret = ppobj->ReadLog(hr, min, date, month);

				if (bret == FALSE)
				{
					cout << "ERROR : Unable to read Specified Log file" << endl;

				}

				delete ppobj;
			}
			else if (_stricmp(command[0], "clear") == 0)
			{
				system("cls");
				continue;
			}
			else if (_stricmp(command[0], "help") == 0)
			{
				DisplayHelp();
				continue;
			}
			else if (_stricmp(command[0], "exit") == 0)
			{
				cout << endl << "Terminating the Marvallous ProcMon" << endl;
				break;
			}

			else
			{
				cout << endl << "ERROR : Command not Found !!" << endl;
				continue;
			}
		}
		else if (count == 2)
		{
			if (_stricmp(command[0], "ps") == 0)
			{
				ppobj = new ProcessInfo();

				bret = ppobj->ProcessDisplay(command[1]);

				if (bret == FALSE)
				{
					cout << "ERROR : Unable to Display process information" << endl;
				}
				delete ppobj;
			}
			else if (_stricmp(command[0], "search") == 0)
			{
				ppobj = new ProcessInfo();

				bret = ppobj->ProcessSearch(command[1]);

				if (bret == FALSE)
				{
					cout << "ERROR : There is no such process" << endl;
				}

				delete ppobj;

				continue;
			}
			else if (_stricmp(command[0], "kill") == 0)
			{
				ppobj = new ProcessInfo();

				bret = ppobj->KillProcess(command[1]);

				if (bret == FALSE)
				{
					cout << "ERROR : There is no such Process" << endl;
				}
				else
				{
					cout << command[1] << "Terminated Succesfully" << endl;
				}

				delete ppobj;
				continue;

			}

		}
		else
		{
			cout << endl << "ERROR : Command not Found!!!" << endl;
			continue;
		}
	}
	return 0;
}