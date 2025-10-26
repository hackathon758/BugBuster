import React, { useState, useEffect } from 'react';
import { useNavigate } from 'react-router-dom';
import axios from 'axios';
import { API } from '../App';
import Navigation from '../components/Navigation';
import { Card, CardContent, CardHeader, CardTitle } from '../components/ui/card';
import { Button } from '../components/ui/button';
import { Input } from '../components/ui/input';
import { Label } from '../components/ui/label';
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from '../components/ui/select';
import { Dialog, DialogContent, DialogHeader, DialogTitle, DialogTrigger } from '../components/ui/dialog';
import { toast } from 'sonner';
import { Code, Plus, Calendar, Shield, TrendingUp } from 'lucide-react';
import { Badge } from '../components/ui/badge';

export default function Repositories({ user }) {
  const navigate = useNavigate();
  const [repositories, setRepositories] = useState([]);
  const [loading, setLoading] = useState(true);
  const [dialogOpen, setDialogOpen] = useState(false);
  const [formData, setFormData] = useState({
    name: '',
    description: '',
    language: 'python'
  });

  const languages = [
    { value: 'python', label: 'Python' },
    { value: 'javascript', label: 'JavaScript' },
    { value: 'typescript', label: 'TypeScript' },
    { value: 'java', label: 'Java' },
    { value: 'cpp', label: 'C++' },
    { value: 'go', label: 'Go' },
    { value: 'rust', label: 'Rust' },
    { value: 'php', label: 'PHP' },
  ];

  useEffect(() => {
    fetchRepositories();
  }, []);

  const fetchRepositories = async () => {
    try {
      const response = await axios.get(`${API}/repositories`);
      setRepositories(response.data);
    } catch (error) {
      toast.error('Failed to fetch repositories');
    } finally {
      setLoading(false);
    }
  };

  const handleCreateRepository = async (e) => {
    e.preventDefault();
    try {
      await axios.post(`${API}/repositories`, formData);
      toast.success('Repository created successfully');
      setDialogOpen(false);
      setFormData({ name: '', description: '', language: 'python' });
      fetchRepositories();
    } catch (error) {
      toast.error(error.response?.data?.detail || 'Failed to create repository');
    }
  };

  const getScoreColor = (score) => {
    if (!score) return 'text-gray-400';
    if (score >= 80) return 'text-green-600';
    if (score >= 60) return 'text-yellow-600';
    if (score >= 40) return 'text-orange-600';
    return 'text-red-600';
  };

  const getSeverityIcon = (severity) => {
    const icons = {
      critical: <AlertTriangle className="w-4 h-4 text-red-600" />,
      high: <AlertTriangle className="w-4 h-4 text-orange-600" />,
      medium: <AlertTriangle className="w-4 h-4 text-yellow-600" />,
      low: <Info className="w-4 h-4 text-blue-600" />,
      info: <Info className="w-4 h-4 text-gray-600" />
    };
    return icons[severity] || icons.info;
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

  const toggleRepoVulnerabilities = async (repoId) => {
    const isExpanded = expandedRepos[repoId];
    
    setExpandedRepos(prev => ({
      ...prev,
      [repoId]: !isExpanded
    }));

    // Fetch vulnerabilities if not already loaded and expanding
    if (!isExpanded && !repoVulnerabilities[repoId]) {
      setLoadingVulns(prev => ({ ...prev, [repoId]: true }));
      try {
        const response = await axios.get(`${API}/repositories/${repoId}/vulnerabilities`);
        setRepoVulnerabilities(prev => ({
          ...prev,
          [repoId]: response.data
        }));
      } catch (error) {
        toast.error('Failed to fetch vulnerabilities');
      } finally {
        setLoadingVulns(prev => ({ ...prev, [repoId]: false }));
      }
    }
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
      
      <div className="max-w-7xl mx-auto p-6 lg:p-8" data-testid="repositories-container">
        {/* Header */}
        <div className="flex items-center justify-between mb-8">
          <div>
            <h1 className="text-4xl font-bold text-gray-900 mb-2" style={{ fontFamily: 'Space Grotesk, sans-serif' }}>
              Repositories
            </h1>
            <p className="text-gray-600">Manage your code repositories and security scans</p>
          </div>
          
          <Dialog open={dialogOpen} onOpenChange={setDialogOpen}>
            <DialogTrigger asChild>
              <Button className="bg-gradient-to-r from-blue-600 to-teal-500 hover:from-blue-700 hover:to-teal-600" data-testid="add-repository-button">
                <Plus className="w-4 h-4 mr-2" />
                Add Repository
              </Button>
            </DialogTrigger>
            <DialogContent className="sm:max-w-md">
              <DialogHeader>
                <DialogTitle>Add New Repository</DialogTitle>
              </DialogHeader>
              <form onSubmit={handleCreateRepository} className="space-y-4 mt-4">
                <div>
                  <Label htmlFor="name">Repository Name</Label>
                  <Input
                    id="name"
                    value={formData.name}
                    onChange={(e) => setFormData({ ...formData, name: e.target.value })}
                    placeholder="my-awesome-project"
                    required
                    className="mt-1.5"
                    data-testid="repo-name-input"
                  />
                </div>
                
                <div>
                  <Label htmlFor="description">Description (Optional)</Label>
                  <Input
                    id="description"
                    value={formData.description}
                    onChange={(e) => setFormData({ ...formData, description: e.target.value })}
                    placeholder="A brief description"
                    className="mt-1.5"
                    data-testid="repo-description-input"
                  />
                </div>

                <div>
                  <Label htmlFor="language">Primary Language</Label>
                  <Select value={formData.language} onValueChange={(value) => setFormData({ ...formData, language: value })}>
                    <SelectTrigger className="mt-1.5" data-testid="repo-language-select">
                      <SelectValue />
                    </SelectTrigger>
                    <SelectContent>
                      {languages.map((lang) => (
                        <SelectItem key={lang.value} value={lang.value}>
                          {lang.label}
                        </SelectItem>
                      ))}
                    </SelectContent>
                  </Select>
                </div>

                <Button type="submit" className="w-full" data-testid="create-repo-button">
                  Create Repository
                </Button>
              </form>
            </DialogContent>
          </Dialog>
        </div>

        {/* Repositories Grid */}
        {repositories.length > 0 ? (
          <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-6">
            {repositories.map((repo) => (
              <Card key={repo.id} className="bg-white/80 backdrop-blur-sm border-gray-200 hover:shadow-lg transition-all" data-testid="repository-card">
                <CardHeader>
                  <div className="flex items-start justify-between">
                    <div className="flex-1">
                      <CardTitle className="text-lg mb-2" style={{ fontFamily: 'Space Grotesk, sans-serif' }}>
                        {repo.name}
                      </CardTitle>
                      {repo.description && (
                        <p className="text-sm text-gray-600 line-clamp-2">{repo.description}</p>
                      )}
                    </div>
                    <Code className="w-5 h-5 text-gray-400 flex-shrink-0 ml-2" />
                  </div>
                </CardHeader>
                <CardContent>
                  <div className="space-y-3">
                    {/* Language */}
                    <div className="flex items-center gap-2">
                      <Badge variant="outline" className="capitalize">
                        {repo.language}
                      </Badge>
                    </div>

                    {/* Security Score */}
                    {repo.security_score !== null && repo.security_score !== undefined ? (
                      <div className="flex items-center justify-between p-3 bg-gray-50 rounded-lg">
                        <div className="flex items-center gap-2">
                          <Shield className="w-4 h-4 text-gray-600" />
                          <span className="text-sm text-gray-600">Security Score</span>
                        </div>
                        <span className={`text-xl font-bold ${getScoreColor(repo.security_score)}`}>
                          {repo.security_score}
                        </span>
                      </div>
                    ) : (
                      <div className="flex items-center justify-center p-3 bg-gray-50 rounded-lg text-sm text-gray-500">
                        No scans yet
                      </div>
                    )}

                    {/* Last Scan */}
                    {repo.last_scan && (
                      <div className="flex items-center gap-2 text-xs text-gray-500">
                        <Calendar className="w-3 h-3" />
                        Last scan: {new Date(repo.last_scan).toLocaleDateString()}
                      </div>
                    )}

                    {/* Created Date */}
                    <div className="flex items-center gap-2 text-xs text-gray-500">
                      <TrendingUp className="w-3 h-3" />
                      Created: {new Date(repo.created_at).toLocaleDateString()}
                    </div>

                    {/* Vulnerabilities Section */}
                    {repo.security_score !== null && repo.security_score !== undefined && (
                      <div className="pt-3 border-t border-gray-200">
                        <button
                          onClick={() => toggleRepoVulnerabilities(repo.id)}
                          className="w-full flex items-center justify-between p-2 hover:bg-gray-50 rounded-lg transition-colors"
                        >
                          <div className="flex items-center gap-2">
                            <AlertTriangle className="w-4 h-4 text-gray-600" />
                            <span className="text-sm font-medium text-gray-700">Vulnerabilities</span>
                          </div>
                          {expandedRepos[repo.id] ? (
                            <ChevronUp className="w-4 h-4 text-gray-500" />
                          ) : (
                            <ChevronDown className="w-4 h-4 text-gray-500" />
                          )}
                        </button>

                        {expandedRepos[repo.id] && (
                          <div className="mt-3 space-y-3">
                            {loadingVulns[repo.id] ? (
                              <div className="flex items-center justify-center py-4">
                                <div className="animate-spin rounded-full h-6 w-6 border-b-2 border-blue-600"></div>
                              </div>
                            ) : repoVulnerabilities[repo.id] ? (
                              <>
                                {/* Severity Counts */}
                                <div className="grid grid-cols-2 gap-2">
                                  {repoVulnerabilities[repo.id].severity_counts.critical > 0 && (
                                    <div className="flex items-center gap-1 text-xs">
                                      <Badge className="bg-red-100 text-red-800 text-xs px-2 py-0.5">
                                        Critical: {repoVulnerabilities[repo.id].severity_counts.critical}
                                      </Badge>
                                    </div>
                                  )}
                                  {repoVulnerabilities[repo.id].severity_counts.high > 0 && (
                                    <div className="flex items-center gap-1 text-xs">
                                      <Badge className="bg-orange-100 text-orange-800 text-xs px-2 py-0.5">
                                        High: {repoVulnerabilities[repo.id].severity_counts.high}
                                      </Badge>
                                    </div>
                                  )}
                                  {repoVulnerabilities[repo.id].severity_counts.medium > 0 && (
                                    <div className="flex items-center gap-1 text-xs">
                                      <Badge className="bg-yellow-100 text-yellow-800 text-xs px-2 py-0.5">
                                        Medium: {repoVulnerabilities[repo.id].severity_counts.medium}
                                      </Badge>
                                    </div>
                                  )}
                                  {repoVulnerabilities[repo.id].severity_counts.low > 0 && (
                                    <div className="flex items-center gap-1 text-xs">
                                      <Badge className="bg-blue-100 text-blue-800 text-xs px-2 py-0.5">
                                        Low: {repoVulnerabilities[repo.id].severity_counts.low}
                                      </Badge>
                                    </div>
                                  )}
                                </div>

                                {/* Top Vulnerabilities */}
                                {repoVulnerabilities[repo.id].vulnerabilities.length > 0 ? (
                                  <div className="space-y-2 max-h-64 overflow-y-auto">
                                    <p className="text-xs font-semibold text-gray-700 mb-2">
                                      Recent Issues ({repoVulnerabilities[repo.id].total_vulnerabilities} total):
                                    </p>
                                    {repoVulnerabilities[repo.id].vulnerabilities.slice(0, 5).map((vuln) => (
                                      <div
                                        key={vuln.id}
                                        className="p-2 bg-gray-50 rounded border border-gray-200 text-xs"
                                      >
                                        <div className="flex items-start gap-2 mb-1">
                                          {getSeverityIcon(vuln.severity)}
                                          <div className="flex-1">
                                            <p className="font-medium text-gray-800 line-clamp-1">
                                              {vuln.title}
                                            </p>
                                            <p className="text-gray-600 text-xs mt-1 line-clamp-2">
                                              {vuln.description}
                                            </p>
                                            {vuln.file_path && (
                                              <p className="text-gray-500 text-xs mt-1">
                                                {vuln.file_path}
                                                {vuln.line_number && ` (Line ${vuln.line_number})`}
                                              </p>
                                            )}
                                          </div>
                                        </div>
                                      </div>
                                    ))}
                                    {repoVulnerabilities[repo.id].total_vulnerabilities > 5 && (
                                      <p className="text-xs text-gray-500 text-center pt-1">
                                        + {repoVulnerabilities[repo.id].total_vulnerabilities - 5} more
                                      </p>
                                    )}
                                  </div>
                                ) : (
                                  <div className="text-center py-3 text-xs text-gray-500">
                                    No vulnerabilities found
                                  </div>
                                )}
                              </>
                            ) : null}
                          </div>
                        )}
                      </div>
                    )}
                  </div>
                </CardContent>
              </Card>
            ))}
          </div>
        ) : (
          <Card className="bg-white/80 backdrop-blur-sm border-gray-200 border-dashed">
            <CardContent className="flex flex-col items-center justify-center py-16">
              <Code className="w-16 h-16 text-gray-400 mb-4" />
              <h3 className="text-lg font-semibold text-gray-700 mb-2">No Repositories Yet</h3>
              <p className="text-gray-500 text-center max-w-sm mb-6">
                Get started by adding your first repository to begin security scanning.
              </p>
              <Button onClick={() => setDialogOpen(true)} className="bg-gradient-to-r from-blue-600 to-teal-500">
                <Plus className="w-4 h-4 mr-2" />
                Add Your First Repository
              </Button>
            </CardContent>
          </Card>
        )}
      </div>
    </div>
  );
}
