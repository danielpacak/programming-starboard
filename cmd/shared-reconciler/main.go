package main

import (
	"context"
	"fmt"
	"os"

	"github.com/aquasecurity/starboard/pkg/config"
	"github.com/aquasecurity/starboard/pkg/configauditreport"
	"github.com/aquasecurity/starboard/pkg/kube"
	"github.com/aquasecurity/starboard/pkg/operator/controller"
	"github.com/aquasecurity/starboard/pkg/operator/etc"
	"github.com/aquasecurity/starboard/pkg/starboard"
	"k8s.io/client-go/kubernetes"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/log"
	"sigs.k8s.io/controller-runtime/pkg/manager"
)

var (
	setupLog = log.Log.WithName("operator")
)

func main() {
	if err := run(); err != nil {
		os.Exit(1)
	}
}

func run() error {
	operatorConfig, err := etc.GetOperatorConfig()
	if err != nil {
		return fmt.Errorf("getting operator config: %w", err)
	}

	kubeConfig, err := ctrl.GetConfig()
	if err != nil {
		return fmt.Errorf("getting kube client config: %w", err)
	}

	// The only reason we're using kubernetes.Clientset is that we need it to read Pod logs,
	// which is not supported by the client returned by the ctrl.Manager.
	kubeClientset, err := kubernetes.NewForConfig(kubeConfig)
	if err != nil {
		return fmt.Errorf("constructing kube client: %w", err)
	}

	options := manager.Options{}
	mgr, err := ctrl.NewManager(kubeConfig, options)
	if err != nil {
		return err
	}

	configManager := starboard.NewConfigManager(kubeClientset, "default")
	err = configManager.EnsureDefault(context.Background())
	if err != nil {
		return err
	}

	starboardConfig, err := configManager.Read(context.Background())
	if err != nil {
		return err
	}

	ownerResolver := controller.OwnerResolver{Client: mgr.GetClient()}
	limitChecker := controller.NewLimitChecker(operatorConfig, mgr.GetClient())
	logsReader := kube.NewLogsReader(kubeClientset)

	configAuditReportPlugin, err := config.GetConfigAuditReportPlugin(starboard.BuildInfo{}, starboardConfig)
	if err != nil {
		return err
	}

	if err = (&controller.ConfigAuditReportReconciler{
		Logger:        ctrl.Log.WithName("reconciler").WithName("configauditreport"),
		Config:        operatorConfig,
		Client:        mgr.GetClient(),
		OwnerResolver: ownerResolver,
		LimitChecker:  limitChecker,
		LogsReader:    logsReader,
		Plugin:        configAuditReportPlugin,
		ReadWriter:    configauditreport.NewControllerRuntimeReadWriter(mgr.GetClient()),
	}).SetupWithManager(mgr); err != nil {
		return fmt.Errorf("unable to setup configauditreport reconciler: %w", err)
	}

	// regiser webhook
	// register GW ingegration
	// export crd to gPrc dend

	// ConfigAuditReportWatcher to export data somewhere

	setupLog.Info("Starting controllers manager")
	if err := mgr.Start(ctrl.SetupSignalHandler()); err != nil {
		return fmt.Errorf("starting controllers manager: %w", err)
	}

	return nil
}
