#include <bits/stdc++.h>
using namespace std;
int main(){
    ios::sync_with_stdio(false); cin.tie(nullptr);
    int N,G; cin>>N>>G;
    vector<long long> arrivals(N), slots(G);
    for(auto& x:arrivals) cin>>x;
    for(auto& x:slots) cin>>x;
    sort(arrivals.begin(),arrivals.end());
    sort(slots.begin(),slots.end());
    multiset<long long> avail(slots.begin(),slots.end());
    long long total=0;
    for(long long a:arrivals){
        auto it=avail.lower_bound(a);
        total+=*it-a;
        avail.erase(it);
    }
    cout<<total<<"\n";
}