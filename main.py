import os
import traceback

from agent.github_issue import GitRepoAnalyzer


def main():
    """Main function that runs the analysis"""
    print("\n🔍 GitHub Issue Creator - Code Analysis 🔍\n")

    try:
        repo_path = input("Path to local repository: ").rstrip("/")
        target_folder = input("Folder to analyze (relative to repo): ").rstrip("/")

        # Validate paths
        if not os.path.isdir(repo_path):
            print(f"❌ Path {repo_path} doesn't exist or is not a directory")
            return

        folder_path = os.path.join(repo_path, target_folder)
        if not os.path.isdir(folder_path):
            print(f"❌ Folder {target_folder} doesn't exist in the repository")
            return

        # Confirm operation
        print(f"\n📁 Will analyze: {folder_path}")
        confirm = input("Continue? (y/n): ").lower()
        if confirm != "y":
            print("❌ Operation cancelled")
            return

        # Run analysis
        print("\n🚀 Starting analysis...\n")
        analyzer = GitRepoAnalyzer(repo_path, target_folder)
        analyzer.analyze_folder()

        print("\n✅ Analysis completed!\n")

    except KeyboardInterrupt:
        print("\n❌ Operation interrupted by user")
    except Exception as e:
        print(f"\n❌ Error: {e}")
        traceback.print_exc()


if __name__ == "__main__":
    main()
