package main

import (
	"fmt"
	"strconv"

	"github.com/spf13/cobra"

	"github.com/yogenpoonudurai/enki/internal/remediate"
)

func newUndoCmd() *cobra.Command {
	var count int
	var force bool
	cmd := &cobra.Command{
		Use:   "undo [n]",
		Short: "Restore files and permissions changed by enki fix",
		Args:  cobra.MaximumNArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			if len(args) == 1 {
				n, err := strconv.Atoi(args[0])
				if err != nil || n < 1 {
					return fmt.Errorf("invalid count %q", args[0])
				}
				count = n
			}
			msgs, err := remediate.Undo(count, force)
			if err != nil {
				return err
			}
			if len(msgs) == 0 {
				fmt.Println("Nothing to undo.")
				return nil
			}
			for _, m := range msgs {
				fmt.Println("UNDO", m)
			}
			return nil
		},
	}
	cmd.Flags().IntVarP(&count, "count", "n", 1, "number of applied actions to restore")
	cmd.Flags().BoolVar(&force, "force", false, "restore even when the file changed after enki applied it")
	return cmd
}
