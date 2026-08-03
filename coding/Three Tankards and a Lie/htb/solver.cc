#include <bits/stdc++.h>
using namespace std;
int main(){
    ios::sync_with_stdio(false); cin.tie(nullptr);
    int N,M,Q; cin>>N>>M>>Q;
    vector<int> board(N+1);
    for(int i=0;i<=N;i++) board[i]=i;
    for(int i=0;i<M;i++){
        int a,b; cin>>a>>b;
        swap(board[a], board[b]);
    }
    vector<int> final_pos_of(N+1);
    for(int pos=1; pos<=N; pos++) final_pos_of[board[pos]] = pos;
    for(int i=0;i<Q;i++){
        int p; cin>>p;
        cout<<final_pos_of[p]<<"\n";
    }
}
