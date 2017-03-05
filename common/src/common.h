#include <windows.h>
#include <vector>
#include <ctime>
#include <fstream>
#include <algorithm>

using namespace std;

class jsw_timer {
public:
  typedef double diff_type;
public:
  jsw_timer(): start ( std::clock() ), elapsed ( 0.0 ) {}
public:
  void begin() { start = std::clock(); elapsed = 0.0; }
  diff_type end() {
    elapsed = static_cast<diff_type> ( std::clock() ) - start;
    return elapsed /= CLOCKS_PER_SEC;
  }
  diff_type last() const { return elapsed; }
private:
  std::clock_t start;
  diff_type    elapsed;
};

//logging
ofstream out_l;
SYSTEMTIME st;
char timestamp[20];
jsw_timer jt;
jsw_timer jt_tot;
