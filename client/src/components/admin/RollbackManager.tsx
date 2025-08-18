import { useState, useEffect } from "react";
import { useQuery, useMutation, useQueryClient } from "@tanstack/react-query";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { AlertDialog, AlertDialogAction, AlertDialogCancel, AlertDialogContent, AlertDialogDescription, AlertDialogFooter, AlertDialogHeader, AlertDialogTitle } from "@/components/ui/alert-dialog";
import { Badge } from "@/components/ui/badge";
import { Separator } from "@/components/ui/separator";
import { apiRequest } from "@/lib/api";
import { useToast } from "@/hooks/use-toast";
import { Save, RotateCcw, Trash2, Clock, Database, FileText, AlertTriangle, CheckCircle } from "lucide-react";
import { format } from "date-fns";

interface Snapshot {
  id: string;
  timestamp: string;
  description: string;
}

interface RollbackStatus {
  available: boolean;
  totalSnapshots: number;
  latestSnapshot: Snapshot | null;
  maxSnapshots: number;
}

export default function RollbackManager() {
  const [snapshotDescription, setSnapshotDescription] = useState("");
  const [selectedSnapshot, setSelectedSnapshot] = useState<string | null>(null);
  const [showRollbackDialog, setShowRollbackDialog] = useState(false);
  const [showDeleteDialog, setShowDeleteDialog] = useState(false);
  const queryClient = useQueryClient();
  const { toast } = useToast();

  // Fetch rollback status
  const { data: status, isLoading: statusLoading } = useQuery<RollbackStatus>({
    queryKey: ['/api/rollback/status'],
    refetchInterval: 30000 // Refresh every 30 seconds
  });

  // Fetch snapshots list
  const { data: snapshotsData, isLoading: snapshotsLoading } = useQuery<{
    snapshots: Snapshot[];
    total: number;
  }>({
    queryKey: ['/api/rollback/snapshots'],
    refetchInterval: 30000
  });

  // Create snapshot mutation
  const createSnapshotMutation = useMutation({
    mutationFn: async (description: string) => {
      const response = await apiRequest("POST", "/api/rollback/create", {
        description
      });
      return response.json();
    },
    onSuccess: () => {
      toast({
        title: "Snapshot Created",
        description: "System snapshot created successfully",
      });
      setSnapshotDescription("");
      queryClient.invalidateQueries({ queryKey: ['/api/rollback/snapshots'] });
      queryClient.invalidateQueries({ queryKey: ['/api/rollback/status'] });
    },
    onError: (error: any) => {
      toast({
        title: "Snapshot Failed",
        description: error.message || "Failed to create snapshot",
        variant: "destructive",
      });
    }
  });

  // Rollback mutation
  const rollbackMutation = useMutation({
    mutationFn: async (snapshotId: string) => {
      const response = await apiRequest("POST", `/api/rollback/${snapshotId}`);
      return response.json();
    },
    onSuccess: (data) => {
      toast({
        title: "Rollback Completed",
        description: `Successfully rolled back to snapshot. Backup created: ${data.result.backupId}`,
      });
      setShowRollbackDialog(false);
      setSelectedSnapshot(null);
      queryClient.invalidateQueries({ queryKey: ['/api/rollback/snapshots'] });
      queryClient.invalidateQueries({ queryKey: ['/api/rollback/status'] });
    },
    onError: (error: any) => {
      toast({
        title: "Rollback Failed",
        description: error.message || "Failed to rollback to snapshot",
        variant: "destructive",
      });
    }
  });

  // Delete snapshot mutation
  const deleteSnapshotMutation = useMutation({
    mutationFn: async (snapshotId: string) => {
      const response = await apiRequest("DELETE", `/api/rollback/${snapshotId}`);
      return response.json();
    },
    onSuccess: () => {
      toast({
        title: "Snapshot Deleted",
        description: "Snapshot deleted successfully",
      });
      setShowDeleteDialog(false);
      setSelectedSnapshot(null);
      queryClient.invalidateQueries({ queryKey: ['/api/rollback/snapshots'] });
      queryClient.invalidateQueries({ queryKey: ['/api/rollback/status'] });
    },
    onError: (error: any) => {
      toast({
        title: "Delete Failed",
        description: error.message || "Failed to delete snapshot",
        variant: "destructive",
      });
    }
  });

  const handleCreateSnapshot = () => {
    if (snapshotDescription.trim()) {
      createSnapshotMutation.mutate(snapshotDescription.trim());
    }
  };

  const handleRollback = (snapshotId: string) => {
    setSelectedSnapshot(snapshotId);
    setShowRollbackDialog(true);
  };

  const handleDelete = (snapshotId: string) => {
    setSelectedSnapshot(snapshotId);
    setShowDeleteDialog(true);
  };

  const confirmRollback = () => {
    if (selectedSnapshot) {
      rollbackMutation.mutate(selectedSnapshot);
    }
  };

  const confirmDelete = () => {
    if (selectedSnapshot) {
      deleteSnapshotMutation.mutate(selectedSnapshot);
    }
  };

  const isLoading = statusLoading || snapshotsLoading;
  const snapshots = snapshotsData?.snapshots || [];

  return (
    <div className="space-y-6">
      {/* Status Overview */}
      <Card>
        <CardHeader>
          <CardTitle className="flex items-center gap-2">
            <Database className="h-5 w-5" />
            Rollback System Status
          </CardTitle>
        </CardHeader>
        <CardContent>
          {isLoading ? (
            <div className="flex items-center gap-2">
              <div className="animate-spin rounded-full h-4 w-4 border-b-2 border-primary"></div>
              <span className="text-sm text-muted-foreground">Loading status...</span>
            </div>
          ) : status?.available ? (
            <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
              <div className="flex items-center gap-2">
                <CheckCircle className="h-4 w-4 text-green-500" />
                <div>
                  <div className="text-sm font-medium">System Available</div>
                  <div className="text-xs text-muted-foreground">Rollback ready</div>
                </div>
              </div>
              <div className="flex items-center gap-2">
                <FileText className="h-4 w-4 text-blue-500" />
                <div>
                  <div className="text-sm font-medium">{status.totalSnapshots} Snapshots</div>
                  <div className="text-xs text-muted-foreground">Max: {status.maxSnapshots}</div>
                </div>
              </div>
              <div className="flex items-center gap-2">
                <Clock className="h-4 w-4 text-purple-500" />
                <div>
                  <div className="text-sm font-medium">Latest Snapshot</div>
                  <div className="text-xs text-muted-foreground">
                    {status.latestSnapshot 
                      ? format(new Date(status.latestSnapshot.timestamp), 'MMM dd, HH:mm')
                      : 'None'
                    }
                  </div>
                </div>
              </div>
            </div>
          ) : (
            <div className="flex items-center gap-2 text-red-500">
              <AlertTriangle className="h-4 w-4" />
              <span className="text-sm">Rollback system unavailable</span>
            </div>
          )}
        </CardContent>
      </Card>

      {/* Create Snapshot */}
      <Card>
        <CardHeader>
          <CardTitle className="flex items-center gap-2">
            <Save className="h-5 w-5" />
            Create New Snapshot
          </CardTitle>
        </CardHeader>
        <CardContent className="space-y-4">
          <div>
            <Label htmlFor="description">Snapshot Description</Label>
            <Input
              id="description"
              value={snapshotDescription}
              onChange={(e) => setSnapshotDescription(e.target.value)}
              placeholder="Enter a description for this snapshot..."
              className="mt-1"
            />
          </div>
          <Button 
            onClick={handleCreateSnapshot}
            disabled={!snapshotDescription.trim() || createSnapshotMutation.isPending}
            className="w-full"
          >
            {createSnapshotMutation.isPending ? (
              <div className="flex items-center gap-2">
                <div className="animate-spin rounded-full h-4 w-4 border-b-2 border-current"></div>
                Creating Snapshot...
              </div>
            ) : (
              <>
                <Save className="h-4 w-4 mr-2" />
                Create Snapshot
              </>
            )}
          </Button>
        </CardContent>
      </Card>

      {/* Snapshots List */}
      <Card>
        <CardHeader>
          <CardTitle className="flex items-center gap-2">
            <FileText className="h-5 w-5" />
            Available Snapshots
          </CardTitle>
        </CardHeader>
        <CardContent>
          {isLoading ? (
            <div className="flex items-center gap-2">
              <div className="animate-spin rounded-full h-4 w-4 border-b-2 border-primary"></div>
              <span className="text-sm text-muted-foreground">Loading snapshots...</span>
            </div>
          ) : snapshots.length === 0 ? (
            <div className="text-center py-8 text-muted-foreground">
              <FileText className="h-12 w-12 mx-auto mb-4 opacity-50" />
              <p>No snapshots available</p>
              <p className="text-sm">Create your first snapshot to get started</p>
            </div>
          ) : (
            <div className="space-y-4">
              {snapshots.map((snapshot) => (
                <div key={snapshot.id} className="flex items-center justify-between p-4 border rounded-lg">
                  <div className="flex-1">
                    <div className="flex items-center gap-2 mb-1">
                      <span className="font-medium">{snapshot.description}</span>
                      <Badge variant="secondary" className="text-xs">
                        {snapshot.id}
                      </Badge>
                    </div>
                    <div className="text-sm text-muted-foreground">
                      {format(new Date(snapshot.timestamp), 'MMM dd, yyyy HH:mm:ss')}
                    </div>
                  </div>
                  <div className="flex items-center gap-2">
                    <Button
                      variant="outline"
                      size="sm"
                      onClick={() => handleRollback(snapshot.id)}
                      disabled={rollbackMutation.isPending}
                    >
                      <RotateCcw className="h-4 w-4 mr-1" />
                      Rollback
                    </Button>
                    <Button
                      variant="outline"
                      size="sm"
                      onClick={() => handleDelete(snapshot.id)}
                      disabled={deleteSnapshotMutation.isPending}
                      className="text-red-600 hover:text-red-700"
                    >
                      <Trash2 className="h-4 w-4 mr-1" />
                      Delete
                    </Button>
                  </div>
                </div>
              ))}
            </div>
          )}
        </CardContent>
      </Card>

      {/* Rollback Confirmation Dialog */}
      <AlertDialog open={showRollbackDialog} onOpenChange={setShowRollbackDialog}>
        <AlertDialogContent>
          <AlertDialogHeader>
            <AlertDialogTitle>Confirm Rollback</AlertDialogTitle>
            <AlertDialogDescription>
              Are you sure you want to rollback to this snapshot? This action will:
              <ul className="mt-2 space-y-1 text-sm">
                <li>• Restore the database to the snapshot state</li>
                <li>• Restore critical application files</li>
                <li>• Create a backup of the current state</li>
                <li>• Restart the application</li>
              </ul>
              <div className="mt-4 p-3 bg-yellow-50 border border-yellow-200 rounded-lg">
                <strong>Warning:</strong> This action cannot be undone. Make sure you have a recent backup.
              </div>
            </AlertDialogDescription>
          </AlertDialogHeader>
          <AlertDialogFooter>
            <AlertDialogCancel>Cancel</AlertDialogCancel>
            <AlertDialogAction
              onClick={confirmRollback}
              disabled={rollbackMutation.isPending}
              className="bg-red-600 hover:bg-red-700"
            >
              {rollbackMutation.isPending ? (
                <div className="flex items-center gap-2">
                  <div className="animate-spin rounded-full h-4 w-4 border-b-2 border-current"></div>
                  Rolling back...
                </div>
              ) : (
                "Confirm Rollback"
              )}
            </AlertDialogAction>
          </AlertDialogFooter>
        </AlertDialogContent>
      </AlertDialog>

      {/* Delete Confirmation Dialog */}
      <AlertDialog open={showDeleteDialog} onOpenChange={setShowDeleteDialog}>
        <AlertDialogContent>
          <AlertDialogHeader>
            <AlertDialogTitle>Confirm Delete</AlertDialogTitle>
            <AlertDialogDescription>
              Are you sure you want to delete this snapshot? This action cannot be undone.
            </AlertDialogDescription>
          </AlertDialogHeader>
          <AlertDialogFooter>
            <AlertDialogCancel>Cancel</AlertDialogCancel>
            <AlertDialogAction
              onClick={confirmDelete}
              disabled={deleteSnapshotMutation.isPending}
              className="bg-red-600 hover:bg-red-700"
            >
              {deleteSnapshotMutation.isPending ? (
                <div className="flex items-center gap-2">
                  <div className="animate-spin rounded-full h-4 w-4 border-b-2 border-current"></div>
                  Deleting...
                </div>
              ) : (
                "Delete Snapshot"
              )}
            </AlertDialogAction>
          </AlertDialogFooter>
        </AlertDialogContent>
      </AlertDialog>
    </div>
  );
}