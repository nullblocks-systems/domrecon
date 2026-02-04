package main

import (
	"fmt"
	"os"

	"github.com/nullblocks-systems/domrecon/internal/config"
	"github.com/nullblocks-systems/domrecon/internal/pipeline"
	"github.com/nullblocks-systems/domrecon/internal/server"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

var (
	cfgFile string
	version = "0.1.0"
)

func main() {
	rootCmd := &cobra.Command{
		Use:     "domrecon",
		Short:   "Domain reconnaissance tool",
		Long:    `A containerized Go application for domain discovery and security analysis.`,
		Version: version,
	}

	scanCmd := &cobra.Command{
		Use:   "scan [domain]",
		Short: "Run reconnaissance scan on a domain",
		Args:  cobra.ExactArgs(1),
		RunE:  runScan,
	}

	serveCmd := &cobra.Command{
		Use:   "serve",
		Short: "Run as HTTP service",
		RunE:  runServer,
	}

	rootCmd.PersistentFlags().StringVar(&cfgFile, "config", "", "config file (default: /etc/domrecon/config.yaml)")
	rootCmd.PersistentFlags().String("output", "json", "output format: json, text")
	rootCmd.PersistentFlags().String("output-file", "", "write results to file (default: stdout)")
	rootCmd.PersistentFlags().Int("concurrency", 10, "number of concurrent workers")
	rootCmd.PersistentFlags().Bool("verbose", false, "enable verbose logging")

	scanCmd.Flags().Bool("skip-nuclei", false, "skip nuclei vulnerability scanning")
	scanCmd.Flags().Bool("skip-ports", false, "skip port scanning")
	scanCmd.Flags().Bool("skip-dirs", false, "skip directory enumeration")
	scanCmd.Flags().StringSlice("ports", []string{"21", "22", "23", "25", "53", "80", "110", "143", "443", "3306", "3389", "5432", "6379", "8000", "8080", "8443"}, "ports to scan")

	serveCmd.Flags().String("addr", ":8080", "server listen address")

	viper.BindPFlags(rootCmd.PersistentFlags())
	viper.BindPFlags(scanCmd.Flags())
	viper.BindPFlags(serveCmd.Flags())

	rootCmd.AddCommand(scanCmd)
	rootCmd.AddCommand(serveCmd)

	cobra.OnInitialize(initConfig)

	if err := rootCmd.Execute(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

func initConfig() {
	if cfgFile != "" {
		viper.SetConfigFile(cfgFile)
	} else {
		viper.SetConfigName("config")
		viper.SetConfigType("yaml")
		viper.AddConfigPath("/etc/domrecon")
		viper.AddConfigPath("$HOME/.domrecon")
		viper.AddConfigPath(".")
	}

	viper.SetEnvPrefix("DOMRECON")
	viper.AutomaticEnv()

	if err := viper.ReadInConfig(); err != nil {
		if _, ok := err.(viper.ConfigFileNotFoundError); !ok {
			fmt.Fprintf(os.Stderr, "Error reading config: %v\n", err)
		}
	}
}

func runScan(cmd *cobra.Command, args []string) error {
	domain := args[0]

	cfg, err := config.Load()
	if err != nil {
		return fmt.Errorf("failed to load config: %w", err)
	}

	p := pipeline.New(cfg)
	results, err := p.Run(cmd.Context(), domain)
	if err != nil {
		return fmt.Errorf("scan failed: %w", err)
	}

	return results.Output(cfg.OutputFormat, cfg.OutputFile)
}

func runServer(cmd *cobra.Command, args []string) error {
	cfg, err := config.Load()
	if err != nil {
		return fmt.Errorf("failed to load config: %w", err)
	}

	srv := server.New(cfg)
	return srv.Run(cmd.Context())
}
