#include <bits/stdc++.h>
using namespace std;

int main() {
    ios::sync_with_stdio(false);
    cin.tie(nullptr);

    auto read_set = [&](int n) {
        unordered_set<string> s;
        s.reserve(n * 2);
        for (int i = 0; i < n; i++) {
            string name; cin >> name;
            s.insert(move(name));
        }
        return s;
    };

    int c; cin >> c;
    auto clerks = read_set(c);
    int cs; cin >> cs;
    auto countersigners = read_set(cs);
    int r; cin >> r;
    auto couriers = read_set(r);

    int N; cin >> N;
    int answer = 0;

    for (int i = 0; i < N; i++) {
        string clerk, counter, courier;
        cin >> clerk >> counter >> courier;
        if (clerks.count(clerk) && countersigners.count(counter) && couriers.count(courier))
            answer++;
    }

    cout << answer << "\n";
    return 0;
}