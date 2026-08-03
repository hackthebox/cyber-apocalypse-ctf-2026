#include <bits/stdc++.h>
using namespace std;
struct Dinic {
    struct Edge { int to, rev; int cap; };
    vector<vector<Edge>> g;
    vector<int> level, iter;
    Dinic(int n): g(n), level(n), iter(n) {}
    void add_edge(int u, int v, int cap) {
        g[u].push_back({v,(int)g[v].size(),cap});
        g[v].push_back({u,(int)g[u].size()-1,0});
    }
    bool bfs(int s, int t) {
        fill(level.begin(),level.end(),-1); level[s]=0;
        queue<int> q; q.push(s);
        while (!q.empty()) {
            int v=q.front();q.pop();
            for (auto& e:g[v]) if (e.cap>0 && level[e.to]<0) { level[e.to]=level[v]+1; q.push(e.to); }
        }
        return level[t]>=0;
    }
    int dfs(int v, int t, int f) {
        if (v==t) return f;
        for (int& i=iter[v];i<(int)g[v].size();i++) {
            auto& e=g[v][i];
            if (e.cap>0 && level[v]<level[e.to]) {
                int d=dfs(e.to,t,min(f,e.cap));
                if (d>0){e.cap-=d;g[e.to][e.rev].cap+=d;return d;}
            }
        }
        return 0;
    }
    int max_flow(int s, int t) {
        int flow=0;
        while (bfs(s,t)) { fill(iter.begin(),iter.end(),0); int f; while((f=dfs(s,t,1e9))>0) flow+=f; }
        return flow;
    }
};
int main(){
    ios::sync_with_stdio(false); cin.tie(nullptr);
    int N,E,S,T; cin>>N>>E>>S>>T;
    const int INF=1e9;
    Dinic d(2*N);
    for(int i=0;i<N;i++) d.add_edge(2*i,2*i+1,(i==S||i==T)?INF:1);
    for(int i=0;i<E;i++){int u,v;cin>>u>>v;d.add_edge(2*u+1,2*v,INF);}
    cout<<d.max_flow(2*S+1,2*T)<<"\n";
}