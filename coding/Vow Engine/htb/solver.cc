#include <bits/stdc++.h>
using namespace std;
struct XORDSU {
    vector<int> par,rnk,dist;
    vector<vector<int>> basis;
    XORDSU(int n):par(n),rnk(n,0),dist(n,0),basis(n){iota(par.begin(),par.end(),0);}
    pair<int,int> find(int x){
        if(par[x]==x) return {x,0};
        auto [root,_]=find(par[x]);
        dist[x]^=dist[par[x]]; par[x]=root;
        return {root,dist[x]};
    }
    void ins(int r, int x){
        for(int b:basis[r]) x=min(x,x^b);
        if(x) basis[r].push_back(x);
    }
    void unite(int u,int v,int w){
        auto [ru,du]=find(u); auto [rv,dv]=find(v);
        if(ru==rv){int c=du^dv^w;if(c)ins(ru,c);return;}
        if(rnk[ru]<rnk[rv]){swap(ru,rv);swap(du,dv);}
        par[rv]=ru; dist[rv]=du^dv^w;
        if(rnk[ru]==rnk[rv]) rnk[ru]++;
        for(int b:basis[rv]) ins(ru,b); basis[rv].clear();
    }
    bool query(int u,int v,int T){
        auto [ru,du]=find(u); auto [rv,dv]=find(v);
        if(ru!=rv) return false;
        int t=T^du^dv;
        for(int b:basis[ru]) t=min(t,t^b);
        return t==0;
    }
};
int main(){
    ios::sync_with_stdio(false); cin.tie(nullptr);
    int N,M,Q; cin>>N>>M>>Q;
    XORDSU dsu(N);
    for(int i=0;i<M;i++){int u,v,w;cin>>u>>v>>w;dsu.unite(u,v,w);}
    while(Q--){
        int u,v,T; cin>>u>>v>>T;
        cout<<(dsu.query(u,v,T)?"YES":"NO")<<"\n";
    }
}