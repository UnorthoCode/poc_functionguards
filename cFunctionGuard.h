class cFunctionGuard
{
public:
	cFunctionGuard();
	~cFunctionGuard();
	void FunctionGuard(LPVOID lpCalleeBaseAddr, LPVOID lpCallerBaseAddr);
protected:
	DWORD_PTR GetFunctionSize(LPVOID lpBaseAddr);
	PBYTE HashFunction(LPVOID lpCallerBaseAddr, DWORD dwFunctionSize, DWORD *dwHashLen);
private:
};