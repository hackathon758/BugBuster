import React, { useState, useEffect } from 'react';
import { Link } from 'react-router-dom';
import axios from 'axios';
import { API } from '../App';
import Navigation from '../components/Navigation';
import { Card, CardContent, CardHeader, CardTitle } from '../components/ui/card';
import { Badge } from '../components/ui/badge';
import { Shield, AlertTriangle, Code, TrendingUp, Activity } from 'lucide-react';

export default function Dashboard({ user }) {
  const [stats, setStats] = useState(null);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    fetchDashboardData();
  }, []);

  const fetchDashboardData = async () => {
    try {
      const response = await axios.get(`${API}/dashboard/overview`);
      setStats(response.data);
    } catch (error) {
      console.error('Failed to fetch dashboard data:', error);
    } finally {
      setLoading(false);
    }
  };

  const getSeverityColor = (severity) => {
    const colors = {
      critical: 'bg-red-100 text-red-800 border-red-200',
      high: 'bg-orange-100 text-orange-800 border-orange-200',
      medium: 'bg-yellow-100 text-yellow-800 border-yellow-200',
      low: 'bg-blue-100 text-blue-800 border-blue-200',
      info: 'bg-gray-100 text-gray-800 border-gray-200'
    };
    return colors[severity] || colors.info;
  };

  const getScoreColor = (score) => {
    if (score >= 80) return 'text-green-600';
    if (score >= 60) return 'text-yellow-600';
    if (score >= 40) return 'text-orange-600';
    return 'text-red-600';
  };

  if (loading) {
    return (
      <div className="min-h-screen bg-gradient-to-br from-slate-50 to-blue-50">
        <Navigation user={user} />
        <div className="flex items-center justify-center h-[80vh]">
          <div className="animate-spin rounded-full h-12 w-12 border-b-2 border-blue-600"></div>
        </div>
      </div>
    );
  }

  return (
    <div className="min-h-screen bg-gradient-to-br from-slate-50 to-blue-50">
      <Navigation user={user} />
      
      <div className="max-w-7xl mx-auto p-6 lg:p-8" data-testid="dashboard-container">
        {/* Header */}
        <div className="mb-8">
          <h1 className="text-4xl font-bold text-gray-900 mb-2" style={{ fontFamily: 'Space Grotesk, sans-serif' }}>Security Dashboard</h1>
          <p className="text-gray-600">Welcome back, {user?.name}! Here's your security overview.</p>
        </div>

        {/* Stats Grid */}
        <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-6 mb-8">
          {/* Security Score */}
          <Card className="bg-white/80 backdrop-blur-sm border-gray-200 hover:shadow-lg transition-shadow" data-testid="security-score-card">
            <CardHeader className="pb-3">
              <CardTitle className="text-sm font-medium text-gray-600 flex items-center gap-2">
                <Shield className="w-4 h-4" />
                Security Score
              </CardTitle>
            </CardHeader>
            <CardContent>
              <div className={`text-4xl font-bold ${getScoreColor(stats?.average_security_score || 0)}`}>
                {stats?.average_security_score || 0}
              </div>
              <p className="text-xs text-gray-500 mt-2">Out of 100</p>
            </CardContent>
          </Card>

          {/* Total Vulnerabilities */}
          <Card className="bg-white/80 backdrop-blur-sm border-gray-200 hover:shadow-lg transition-shadow" data-testid="vulnerabilities-card">
            <CardHeader className="pb-3">
              <CardTitle className="text-sm font-medium text-gray-600 flex items-center gap-2">
                <AlertTriangle className="w-4 h-4" />
                Vulnerabilities
              </CardTitle>
            </CardHeader>
            <CardContent>
              <div className="text-4xl font-bold text-gray-900">
                {stats?.total_vulnerabilities || 0}
              </div>
              <p className="text-xs text-gray-500 mt-2">Total found</p>
            </CardContent>
          </Card>

          {/* Repositories */}
          <Card className="bg-white/80 backdrop-blur-sm border-gray-200 hover:shadow-lg transition-shadow" data-testid="repositories-card">
            <CardHeader className="pb-3">
              <CardTitle className="text-sm font-medium text-gray-600 flex items-center gap-2">
                <Code className="w-4 h-4" />
                Repositories
              </CardTitle>
            </CardHeader>
            <CardContent>
              <div className="text-4xl font-bold text-gray-900">
                {stats?.repositories_count || 0}
              </div>
              <p className="text-xs text-gray-500 mt-2">Connected</p>
            </CardContent>
          </Card>

          {/* Scans */}
          <Card className="bg-white/80 backdrop-blur-sm border-gray-200 hover:shadow-lg transition-shadow" data-testid="scans-card">
            <CardHeader className="pb-3">
              <CardTitle className="text-sm font-medium text-gray-600 flex items-center gap-2">
                <Activity className="w-4 h-4" />
                Total Scans
              </CardTitle>
            </CardHeader>
            <CardContent>
              <div className="text-4xl font-bold text-gray-900">
                {stats?.scans_count || 0}
              </div>
              <p className="text-xs text-gray-500 mt-2">Completed</p>
            </CardContent>
          </Card>
        </div>

        {/* Severity Breakdown */}
        {stats?.severity_breakdown && Object.keys(stats.severity_breakdown).length > 0 && (
          <Card className="mb-8 bg-white/80 backdrop-blur-sm border-gray-200" data-testid="severity-breakdown-card">
            <CardHeader>
              <CardTitle className="flex items-center gap-2" style={{ fontFamily: 'Space Grotesk, sans-serif' }}>
                <TrendingUp className="w-5 h-5" />
                Vulnerability Breakdown
              </CardTitle>
            </CardHeader>
            <CardContent>
              <div className="grid grid-cols-2 md:grid-cols-5 gap-4">
                {['critical', 'high', 'medium', 'low', 'info'].map((severity) => (
                  <div key={severity} className="text-center">
                    <Badge className={`${getSeverityColor(severity)} px-4 py-2 text-sm font-semibold capitalize border`}>
                      {severity}
                    </Badge>
                    <p className="text-2xl font-bold text-gray-900 mt-2">
                      {stats.severity_breakdown[severity] || 0}
                    </p>
                  </div>
                ))}
              </div>
            </CardContent>
          </Card>
        )}

        {/* Recent Scans */}
        {stats?.recent_scans && stats.recent_scans.length > 0 && (
          <Card className="bg-white/80 backdrop-blur-sm border-gray-200" data-testid="recent-scans-card">
            <CardHeader>
              <CardTitle style={{ fontFamily: 'Space Grotesk, sans-serif' }}>Recent Scans</CardTitle>
            </CardHeader>
            <CardContent>
              <div className="space-y-4">
                {stats.recent_scans.map((scan) => (
                  <div key={scan.id} className="flex items-center justify-between p-4 bg-gray-50 rounded-xl border border-gray-100">
                    <div className="flex-1">
                      <p className="font-semibold text-gray-900">Scan #{scan.id.slice(0, 8)}</p>
                      <p className="text-sm text-gray-600 mt-1">
                        {new Date(scan.started_at).toLocaleString()}
                      </p>
                    </div>
                    <div className="text-right">
                      <Badge className={scan.status === 'completed' ? 'bg-green-100 text-green-800' : 'bg-yellow-100 text-yellow-800'}>
                        {scan.status}
                      </Badge>
                      {scan.security_score && (
                        <p className={`text-lg font-bold mt-1 ${getScoreColor(scan.security_score)}`}>
                          Score: {scan.security_score}
                        </p>
                      )}
                    </div>
                  </div>
                ))}
              </div>
            </CardContent>
          </Card>
        )}

        {/* Quick Actions */}
        <div className="grid grid-cols-1 md:grid-cols-3 gap-6 mt-8">
          <Link to="/analyze" data-testid="quick-analyze-link">
            <Card className="bg-gradient-to-br from-blue-500 to-blue-600 text-white hover:from-blue-600 hover:to-blue-700 transition-all cursor-pointer h-full">
              <CardContent className="flex flex-col items-center justify-center p-8">
                <Code className="w-12 h-12 mb-4" />
                <h3 className="text-xl font-semibold mb-2">Analyze Code</h3>
                <p className="text-blue-100 text-center text-sm">Real-time code analysis</p>
              </CardContent>
            </Card>
          </Link>

          <Link to="/scanner" data-testid="quick-scan-link">
            <Card className="bg-gradient-to-br from-teal-500 to-teal-600 text-white hover:from-teal-600 hover:to-teal-700 transition-all cursor-pointer h-full">
              <CardContent className="flex flex-col items-center justify-center p-8">
                <Shield className="w-12 h-12 mb-4" />
                <h3 className="text-xl font-semibold mb-2">Scan Repository</h3>
                <p className="text-teal-100 text-center text-sm">Full repository security scan</p>
              </CardContent>
            </Card>
          </Link>

          <Link to="/vulnerabilities" data-testid="quick-vulnerabilities-link">
            <Card className="bg-gradient-to-br from-purple-500 to-purple-600 text-white hover:from-purple-600 hover:to-purple-700 transition-all cursor-pointer h-full">
              <CardContent className="flex flex-col items-center justify-center p-8">
                <AlertTriangle className="w-12 h-12 mb-4" />
                <h3 className="text-xl font-semibold mb-2">View Vulnerabilities</h3>
                <p className="text-purple-100 text-center text-sm">All security findings</p>
              </CardContent>
            </Card>
          </Link>
        </div>
      </div>
    </div>
  );
}
