#include "Header.h"

bool _dbg_enabled = false;

void _dbg_cfg(bool enabled) {
	_dbg_enabled = enabled;
}

basic_ostream<char>* _dbg(const char* func, int line) {
	std::cout.clear();
	if (!_dbg_enabled) {
		std::cout.setstate(std::ios::failbit);
	}
	else {
		time_t rawtime;
		struct tm* timeinfo;
		char buffer[80];

		time(&rawtime);
		timeinfo = localtime(&rawtime);

		strftime(buffer, 80, "%d-%m-%Y %I:%M:%S", timeinfo);
		std::string timeStr(buffer);

		cout << endl << "[" << timeStr << "] " << func << ":" << line << " | ";
	}
	return &cout;
}
