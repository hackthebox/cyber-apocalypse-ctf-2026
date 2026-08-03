#include <bits/stdc++.h>
using namespace std;
int main(){
    ios::sync_with_stdio(false); cin.tie(nullptr);
    int N,P,G; cin>>N>>P>>G;
    vector<string> pattern(P);
    for(auto& s:pattern) cin>>s;
    vector<pair<long long,string>> samples(N);
    for(auto& [t,s]:samples) cin>>t>>s;
    sort(samples.begin(),samples.end());
    const long long INF=1e18;
    vector<long long> dp(P+1,INF);
    dp[0]=-INF;
    for(auto& [ts,typ]:samples){
        for(int j=P;j>=1;j--){
            if(typ==pattern[j-1] && dp[j-1]!=INF){
                if(dp[j-1]==-INF || ts-dp[j-1]>=(long long)G){
                    if(ts<dp[j]) dp[j]=ts;
                }
            }
        }
    }
    for(int j=P;j>=0;j--){
        if(dp[j]<INF){cout<<j<<"\n";return 0;}
    }
    cout<<0<<"\n";
}